package eval

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/debtest"
	"github.com/jd869/debhash/internal/store"
)

var versions = []string{"2.35-0ubuntu3", "2.35-0ubuntu3.1", "2.35-0ubuntu3.8"}

// index builds libc6 in 3 versions (libc.so.6 changes each time, the
// copyright never) and libc6-dev in the same 3 versions (identical headers).
func index(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pub := store.Publication{Distro: "ubuntu", DistroVersion: "22.04", Suite: "jammy-updates", Component: "main", Mirror: "m"}
	file := func(p, body string) deb.Entry {
		return deb.Entry{Path: p, Kind: deb.KindFile, SHA256: debtest.SHA256(body)}
	}
	for _, v := range versions {
		for _, d := range []struct {
			name    string
			entries []deb.Entry
		}{
			{"libc6", []deb.Entry{file("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc "+v), file("/usr/share/doc/libc6/copyright", "GPL")}},
			{"libc6-dev", []deb.Entry{file("/usr/include/stdio.h", "stdio")}},
		} {
			meta := store.PackageMeta{DebSHA256: debtest.SHA256(d.name + v), Name: d.name, Version: v, Arch: "amd64", Source: "glibc", SourceVersion: v}
			if _, err := st.AddPackage(ctx, meta, pub, d.entries); err != nil {
				t.Fatal(err)
			}
		}
	}
	return st
}

func byStrategy(sums []Summary, s Strategy) Summary {
	for _, x := range sums {
		if x.Strategy == s {
			return x
		}
	}
	return Summary{}
}

func TestSynthetic(t *testing.T) {
	st := index(t)
	sums, cases, err := Synthetic(context.Background(), st, Options{Strategies: []Strategy{StrategyAll, StrategyBinaries}})
	if err != nil {
		t.Fatal(err)
	}
	all := byStrategy(sums, StrategyAll)
	// libc6: 3 exact (libc.so.6 is version-defining). libc6-dev: headers are
	// identical in every version, so 3 ambiguous with 3 candidates each.
	if all.Queries != 6 || all.ExactCorrect != 3 || all.Ambiguous != 3 || all.Wrong != 0 || all.MeanCandidates != 3 {
		t.Fatalf("all = %+v", all)
	}
	bin := byStrategy(sums, StrategyBinaries)
	// Only libc6 ships a library; libc6-dev has none and is skipped.
	if bin.Queries != 3 || bin.ExactCorrect != 3 || bin.Skipped != 3 {
		t.Fatalf("binaries = %+v", bin)
	}
	if len(cases) != 12 {
		t.Fatalf("cases = %d", len(cases))
	}
}

func TestMissingCountsOverPromises(t *testing.T) {
	st := index(t)
	sums, cases, err := Missing(context.Background(), st, Options{Strategies: []Strategy{StrategyAll}})
	if err != nil {
		t.Fatal(err)
	}
	s := byStrategy(sums, StrategyAll)
	// With its own deb hidden, nothing can be exact-correct.
	if s.ExactCorrect != 0 || s.Queries != 6 {
		t.Fatalf("missing = %+v", s)
	}
	// libc6 hidden: its libc.so.6 contradicts both remaining versions, so
	// it is flagged "installed version not in index" rather than answered.
	// libc6-dev hidden: its header is identical in every version, so the
	// other versions fit perfectly: wrong, but never exact.
	if s.Flagged != 3 || s.Wrong != 3 || s.ExactWrong != 0 {
		t.Fatalf("missing = %+v (%+v)", s, cases)
	}
}

func TestTouchedAndOne(t *testing.T) {
	st := index(t)
	touched := map[string]bool{"/lib/x86_64-linux-gnu/libc.so.6": true} // merged-/usr spelling
	sums, _, err := Synthetic(context.Background(), st, Options{Strategies: []Strategy{StrategyTouched, StrategyOne}, Touched: touched, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if s := byStrategy(sums, StrategyTouched); s.Queries != 3 || s.ExactCorrect != 3 || s.Skipped != 3 {
		t.Fatalf("touched = %+v", s)
	}
	if s := byStrategy(sums, StrategyOne); s.Queries != 6 || s.Wrong != 0 {
		t.Fatalf("one = %+v", s)
	}
}

func TestTruth(t *testing.T) {
	st := index(t)
	files := []attest.File{
		{Path: "/usr/lib/x86_64-linux-gnu/libc.so.6", SHA256: debtest.SHA256("libc 2.35-0ubuntu3.1")},
		{Path: "/usr/include/stdio.h", SHA256: debtest.SHA256("stdio")},
	}
	dpkg, err := ReadDpkg(strings.NewReader("libc6\t2.35-0ubuntu3.1\tamd64\nlibc6-dev:amd64\t2.35-0ubuntu3.1\tamd64\ntzdata\t2024a-0ubuntu0.22.04\tall\n"))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Truth(context.Background(), st, files, dpkg, store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	// libc6 exact; libc6-dev pinned through libc6 (same source); tzdata is
	// installed, not touched, and its version is not indexed.
	if tr.ExactCorrect != 2 || len(tr.Wrong) != 0 || tr.Unidentified != 1 || len(tr.IndexGaps) != 1 || tr.IndexGaps[0] != "tzdata 2024a-0ubuntu0.22.04" {
		t.Fatalf("truth = %+v", tr)
	}
}

// Libraries are opened through soname symlinks; the touched strategy must
// follow them to the regular file the package ships.
func TestTouchedFollowsSymlinks(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pub := store.Publication{Distro: "ubuntu", DistroVersion: "22.04", Suite: "jammy", Component: "main", Mirror: "m"}
	if _, err := st.AddPackage(ctx, store.PackageMeta{DebSHA256: "x", Name: "libcap2", Version: "1:2.44-1build3", Arch: "amd64"}, pub, []deb.Entry{
		{Path: "/lib/x86_64-linux-gnu/libcap.so.2.44", Kind: deb.KindFile, SHA256: debtest.SHA256("cap")},
		{Path: "/lib/x86_64-linux-gnu/libcap.so.2", Kind: deb.KindSymlink, LinkTarget: "libcap.so.2.44"},
	}); err != nil {
		t.Fatal(err)
	}
	sums, _, err := Synthetic(ctx, st, Options{Strategies: []Strategy{StrategyTouched},
		Touched: map[string]bool{"/usr/lib/x86_64-linux-gnu/libcap.so.2": true}})
	if err != nil {
		t.Fatal(err)
	}
	if s := byStrategy(sums, StrategyTouched); s.Queries != 1 || s.ExactCorrect != 1 {
		t.Fatalf("touched via symlink = %+v", s)
	}
}
