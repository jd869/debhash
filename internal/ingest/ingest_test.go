package ingest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jd869/debhash/internal/debtest"
	"github.com/jd869/debhash/internal/launchpad"
	"github.com/jd869/debhash/internal/launchpad/lptest"
	"github.com/jd869/debhash/internal/store"
)

// fakeRepo serves a minimal Ubuntu-style mirror with two pockets.
type fakeRepo struct {
	files map[string][]byte
	mu    sync.Mutex
	flaky map[string]int // path -> remaining requests to refuse
}

func (f *fakeRepo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	if f.flaky[path] > 0 {
		f.flaky[path]--
		f.mu.Unlock()
		http.Error(w, "flaky", http.StatusNotFound) // not retried by GetURL
		return
	}
	f.mu.Unlock()
	b, ok := f.files[path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

type debSpec struct {
	name, version, arch, file, body string
	link                            string // if set, file is a symlink to this
	tamper                          bool
}

// addSuite publishes debs in dists/<suite> with Packages.gz, Contents and Release.
func (f *fakeRepo) addSuite(t *testing.T, suite string, debs []debSpec) {
	var packages, contents strings.Builder
	for _, d := range debs {
		raw := buildDeb(t, d)
		pool := fmt.Sprintf("pool/main/%s/%s_%s_%s.deb", d.name, d.name, d.version, d.arch)
		sum := debtest.SHA256Bytes(raw)
		if d.tamper {
			// Still a parseable deb, but no longer the one Packages vouches for.
			raw = append(append([]byte{}, raw...), '\n', '\n')
		}
		f.files[pool] = raw
		fmt.Fprintf(&packages, "Package: %s\nVersion: %s\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\nDescription: x\n continuation\n\n",
			d.name, d.version, d.arch, pool, len(raw), sum)
		fmt.Fprintf(&contents, "%s    libs/%s\n", strings.TrimPrefix(d.file, "/"), d.name)
	}
	pk := debtest.Gzip(t, []byte(packages.String()))
	ct := debtest.Gzip(t, []byte(contents.String()))
	f.files["dists/"+suite+"/main/binary-arm64/Packages.gz"] = pk
	f.files["dists/"+suite+"/Contents-arm64.gz"] = ct
	f.files["dists/"+suite+"/Release"] = []byte(fmt.Sprintf("Origin: Ubuntu\nVersion: 24.04\nSuite: %s\nSHA256:\n %s %d main/binary-arm64/Packages.gz\n %s %d Contents-arm64.gz\n",
		suite, debtest.SHA256Bytes(pk), len(pk), debtest.SHA256Bytes(ct), len(ct)))
}

func buildDeb(t *testing.T, d debSpec) []byte {
	return debtest.Build(t, debtest.Spec{
		Control:     fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n", d.name, d.version, d.arch),
		Compression: ".zst",
		Files:       []debtest.File{{Path: "." + d.file, Body: d.body, Link: d.link}},
	})
}

func TestRunTargetedTwoPockets(t *testing.T) {
	repo := &fakeRepo{files: map[string][]byte{}}
	repo.addSuite(t, "noble", []debSpec{
		{name: "libfoo1", version: "1.0", arch: "arm64", file: "/usr/lib/aarch64-linux-gnu/libfoo.so.1", body: "foo v1.0"},
		{name: "base-files", version: "13", arch: "arm64", file: "/usr/lib/os-release", body: "VERSION=24.04"},
		{name: "libbad", version: "1", arch: "arm64", file: "/usr/lib/libbad.so", body: "bad", tamper: true},
	})
	repo.addSuite(t, "noble-updates", []debSpec{
		{name: "libfoo1", version: "1.1", arch: "arm64", file: "/usr/lib/aarch64-linux-gnu/libfoo.so.1", body: "foo v1.1"},
	})
	srv := httptest.NewServer(repo)
	defer srv.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	opts := Options{
		Mirror: srv.URL, Suite: "noble", Pockets: []string{"release", "updates"},
		Components: []string{"main"}, Arch: "arm64", Workers: 2,
		// /lib spelling must match the /usr/lib path in Contents (merged /usr).
		Targets: []string{"/lib/aarch64-linux-gnu/libfoo.so.1", "/usr/lib/libbad.so", "/opt/not/packaged"},
	}
	ctx := context.Background()
	rep, err := Run(ctx, st, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Indexes != 2 || rep.TargetPaths != 3 || rep.FoundPaths != 2 {
		t.Fatalf("report = %+v", rep)
	}
	// libfoo1 x2 versions + libbad; base-files not targeted.
	if rep.UniqueDebs != 3 || rep.Downloaded != 2 || len(rep.Failed) != 1 || !strings.Contains(rep.Failed[0], "sha256 mismatch") {
		t.Fatalf("report = %+v", rep)
	}

	res, err := st.Lookup(ctx, []string{debtest.SHA256("foo v1.0"), debtest.SHA256("foo v1.1"), debtest.SHA256("VERSION=24.04")}, store.Filter{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("want both libfoo versions, base-files absent; got %d results", len(res))
	}
	c := res[debtest.SHA256("foo v1.1")].Candidates[0]
	if c.Version != "1.1" || c.Suite != "noble-updates" || c.PURL != "pkg:deb/ubuntu/libfoo1@1.1?arch=arm64&distro=ubuntu-24.04" {
		t.Fatalf("candidate = %+v", c)
	}

	// Second run: nothing new to download; existing debs only gain publications.
	rep2, err := Run(ctx, st, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.AlreadyHad != 2 || rep2.Downloaded != 0 {
		t.Fatalf("re-run should be incremental: %+v", rep2)
	}
}

func TestRunRequiresSelection(t *testing.T) {
	if _, err := Run(context.Background(), nil, Options{}); err == nil {
		t.Fatal("expected error without targets or --all")
	}
}

func TestDistroVersion(t *testing.T) {
	if distroVersion("debian", "12.7") != "12" || distroVersion("ubuntu", "24.04") != "24.04" {
		t.Fatal("distroVersion")
	}
}

func TestRunWithLaunchpadHistory(t *testing.T) {
	v10 := debSpec{name: "libfoo1", version: "1.0", arch: "arm64", file: "/usr/lib/aarch64-linux-gnu/libfoo.so.1", body: "foo v1.0"}
	v11 := debSpec{name: "libfoo1", version: "1.1", arch: "arm64", file: "/usr/lib/aarch64-linux-gnu/libfoo.so.1", body: "foo v1.1"}
	v12 := debSpec{name: "libfoo1", version: "1.2", arch: "arm64", file: "/usr/lib/aarch64-linux-gnu/libfoo.so.1", body: "foo v1.2"}

	// The mirror only has the release version and today's update.
	repo := &fakeRepo{files: map[string][]byte{}}
	repo.addSuite(t, "noble", []debSpec{v10})
	repo.addSuite(t, "noble-updates", []debSpec{v12})
	srv := httptest.NewServer(repo)
	defer srv.Close()

	// Launchpad also knows 1.1, which was current at build time.
	lp := lptest.New(t)
	raw10, raw11, raw12 := buildDeb(t, v10), buildDeb(t, v11), buildDeb(t, v12)
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.0", Pocket: "Release", Published: "2024-04-20T00:00:00+00:00", Superseded: "2025-10-01T00:00:00+00:00", SHA256: debtest.SHA256Bytes(raw10), Body: raw10})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.1", Pocket: "Updates", Published: "2025-10-01T00:00:00+00:00", Superseded: "2025-12-20T00:00:00+00:00", SHA256: debtest.SHA256Bytes(raw11), Body: raw11})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.2", Pocket: "Updates", Published: "2025-12-20T00:00:00+00:00", SHA256: debtest.SHA256Bytes(raw12), Body: raw12})

	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	after, _ := time.Parse("2006-01-02", "2025-09-01")
	before, _ := time.Parse("2006-01-02", "2025-12-10")
	ctx := context.Background()
	rep, err := Run(ctx, st, Options{
		Mirror: srv.URL, Suite: "noble", Pockets: []string{"release", "updates"},
		Components: []string{"main"}, Arch: "arm64", Workers: 2,
		Targets: []string{"/usr/lib/aarch64-linux-gnu/libfoo.so.1"},
		History: &History{Launchpad: &launchpad.Client{API: lp.URL()}, After: after, Before: before},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mirror: 1.0 + 1.2. Launchpad window: 1.0 (same deb, deduped) + 1.1.
	if rep.HistoryDebs != 2 || rep.UniqueDebs != 3 || rep.Downloaded != 3 || len(rep.Failed) != 0 {
		t.Fatalf("report = %+v", rep)
	}
	res, err := st.Lookup(ctx, []string{debtest.SHA256("foo v1.1")}, store.Filter{Suite: "noble", Arch: "arm64"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := res[debtest.SHA256("foo v1.1")]
	if r == nil || r.Candidates[0].Version != "1.1" || r.Candidates[0].Suite != "noble-updates" || r.Candidates[0].DistroVersion != "24.04" {
		t.Fatalf("historical version not indexed correctly: %+v", r)
	}

	if _, err := Run(ctx, st, Options{All: true, History: &History{}}); err == nil {
		t.Fatal("history with --all should be rejected")
	}
}

func TestRunRetriesFailedDownloads(t *testing.T) {
	repo := &fakeRepo{files: map[string][]byte{}}
	repo.addSuite(t, "noble", []debSpec{{name: "libfoo1", version: "1.0", arch: "arm64", file: "/usr/lib/libfoo.so.1", body: "foo"}})
	repo.flaky = map[string]int{"pool/main/libfoo1/libfoo1_1.0_arm64.deb": 1}
	srv := httptest.NewServer(repo)
	defer srv.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rep, err := Run(context.Background(), st, Options{
		Mirror: srv.URL, Suite: "noble", Pockets: []string{"release"}, Components: []string{"main"},
		Arch: "arm64", Targets: []string{"/usr/lib/libfoo.so.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Downloaded != 1 || len(rep.Failed) != 0 {
		t.Fatalf("first failure should be retried and succeed: %+v", rep)
	}
}

func TestRunFollowsSymlinks(t *testing.T) {
	repo := &fakeRepo{files: map[string][]byte{}}
	repo.addSuite(t, "noble", []debSpec{
		{name: "python3-minimal", version: "3.12.3-0ubuntu2", arch: "arm64", file: "/usr/bin/python3", link: "python3.12"},
		{name: "python3.12-minimal", version: "3.12.3-1ubuntu0.8", arch: "arm64", file: "/usr/bin/python3.12", body: "python ELF"},
		{name: "unrelated", version: "1", arch: "arm64", file: "/usr/bin/other", body: "x"},
	})
	srv := httptest.NewServer(repo)
	defer srv.Close()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rep, err := Run(context.Background(), st, Options{
		Mirror: srv.URL, Suite: "noble", Pockets: []string{"release"}, Components: []string{"main"},
		Arch: "arm64", Targets: []string{"/usr/bin/python3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Downloaded != 2 {
		t.Fatalf("want the link owner and the target owner, got %+v", rep)
	}
	res, err := st.Lookup(context.Background(), []string{debtest.SHA256("python ELF")}, store.Filter{}, 0)
	if err != nil || res[debtest.SHA256("python ELF")] == nil {
		t.Fatalf("python3.12 binary not indexed: %v %v", res, err)
	}
}

// Regression: a first run without history already indexed the current
// python3.12-minimal (via the python3 symlink). A later history run must
// still follow the link and fetch the historical version the build used.
func TestHistoryRunFollowsSymlinkAlreadyIndexed(t *testing.T) {
	link := debSpec{name: "python3-minimal", version: "3.12.3-0ubuntu2", arch: "arm64", file: "/usr/bin/python3", link: "python3.12"}
	cur := debSpec{name: "python3.12-minimal", version: "3.12.3-1ubuntu0.17", arch: "arm64", file: "/usr/bin/python3.12", body: "python 0.17"}
	old := debSpec{name: "python3.12-minimal", version: "3.12.3-1ubuntu0.8", arch: "arm64", file: "/usr/bin/python3.12", body: "python 0.8"}

	repo := &fakeRepo{files: map[string][]byte{}}
	repo.addSuite(t, "noble", []debSpec{link, cur})
	srv := httptest.NewServer(repo)
	defer srv.Close()

	lp := lptest.New(t)
	rawLink, rawOld := buildDeb(t, link), buildDeb(t, old)
	lp.Add(lptest.Pub{Name: "python3-minimal", Version: link.version, Pocket: "Release", Published: "2024-04-20T00:00:00+00:00", SHA256: debtest.SHA256Bytes(rawLink), Body: rawLink})
	lp.Add(lptest.Pub{Name: "python3.12-minimal", Version: old.version, Pocket: "Updates", Published: "2025-10-01T00:00:00+00:00", Superseded: "2025-12-20T00:00:00+00:00", SHA256: debtest.SHA256Bytes(rawOld), Body: rawOld})

	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	base := Options{
		Mirror: srv.URL, Suite: "noble", Pockets: []string{"release"}, Components: []string{"main"},
		Arch: "arm64", Targets: []string{"/usr/bin/python3"},
	}
	if _, err := Run(ctx, st, base); err != nil { // step 1: current versions
		t.Fatal(err)
	}
	after, _ := time.Parse("2006-01-02", "2025-09-01")
	before, _ := time.Parse("2006-01-02", "2025-12-10")
	withHistory := base
	withHistory.History = &History{Launchpad: &launchpad.Client{API: lp.URL()}, After: after, Before: before}
	if _, err := Run(ctx, st, withHistory); err != nil { // step 2: history
		t.Fatal(err)
	}
	res, err := st.Lookup(ctx, []string{debtest.SHA256("python 0.8")}, store.Filter{}, 0)
	if err != nil || res[debtest.SHA256("python 0.8")] == nil {
		t.Fatalf("historical python3.12-minimal behind the symlink was not fetched: %v %v", res, err)
	}
}
