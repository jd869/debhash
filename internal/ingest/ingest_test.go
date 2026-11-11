package ingest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
}

func (f *fakeRepo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

type debSpec struct {
	name, version, arch, file, body string
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
		Files:       []debtest.File{{Path: "." + d.file, Body: d.body}},
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
