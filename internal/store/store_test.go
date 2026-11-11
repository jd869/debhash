package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jd869/debhash/internal/deb"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var noble = Publication{Distro: "ubuntu", DistroVersion: "24.04", Suite: "noble-updates", Component: "main", Mirror: "http://m"}

func TestAddAndLookup(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	libc := PackageMeta{DebSHA256: "AAAA", Name: "libc6", Version: "2.39-0ubuntu8.4", Arch: "arm64", Source: "glibc", SourceVersion: "2.39-0ubuntu8.4"}
	id, err := s.AddPackage(ctx, libc, noble, []deb.Entry{
		{Path: "/usr/lib/aarch64-linux-gnu/libc.so.6", Kind: deb.KindFile, SHA256: "11", Size: 10},
		{Path: "/usr/share/doc/libc6/copyright", Kind: deb.KindFile, SHA256: "cc"},
		{Path: "/lib/ld-linux-aarch64.so.1", Kind: deb.KindSymlink, LinkTarget: "aarch64-linux-gnu/ld.so"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A second package sharing the copyright file: fanout 2 for "cc".
	if _, err := s.AddPackage(ctx, PackageMeta{DebSHA256: "bbbb", Name: "libc-bin", Version: "2.39-0ubuntu8.4", Arch: "arm64", Source: "glibc", SourceVersion: "2.39-0ubuntu8.4"}, noble,
		[]deb.Entry{{Path: "/usr/share/doc/libc-bin/copyright", Kind: deb.KindFile, SHA256: "cc"}}); err != nil {
		t.Fatal(err)
	}

	if got, ok, err := s.PackageID(ctx, "aaaa"); err != nil || !ok || got != id {
		t.Fatalf("PackageID case-insensitive lookup = %d %v %v", got, ok, err)
	}
	// Re-adding the same publication is a no-op; a new pocket adds a row.
	if err := s.AddPublication(ctx, id, noble); err != nil {
		t.Fatal(err)
	}
	sec := noble
	sec.Suite = "noble-security"
	if err := s.AddPublication(ctx, id, sec); err != nil {
		t.Fatal(err)
	}

	res, err := s.Lookup(ctx, []string{"11", "CC", "ff"}, Filter{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res["ff"]; ok {
		t.Fatal("unknown hash should be absent")
	}
	if r := res["11"]; r == nil || r.Fanout != 1 || len(r.Candidates) != 2 { // two pockets
		t.Fatalf("libc.so.6 result = %+v", r)
	}
	if r := res["cc"]; r == nil || r.Fanout != 2 {
		t.Fatalf("shared copyright should have fanout 2: %+v", r)
	}
	want := "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4?arch=arm64&upstream=glibc&distro=ubuntu-24.04"
	if got := res["11"].Candidates[0].PURL; got != want {
		t.Fatalf("purl = %s", got)
	}

	// Filters: suite prefix matches pockets; wrong arch / distro excludes.
	for _, tc := range []struct {
		f    Filter
		want int
	}{
		{Filter{Suite: "noble"}, 1},
		{Filter{Suite: "noble-security"}, 1},
		{Filter{Suite: "jammy"}, 0},
		{Filter{Arch: "amd64"}, 0},
		{Filter{Distro: "debian"}, 0},
		{Filter{Distro: "Ubuntu", Arch: "arm64"}, 1},
	} {
		r, err := s.Lookup(ctx, []string{"11"}, tc.f, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(r) != tc.want {
			t.Errorf("filter %+v: got %d results, want %d", tc.f, len(r), tc.want)
		}
	}

	r, _ := s.Lookup(ctx, []string{"11"}, Filter{}, 1)
	if !r["11"].Truncated || len(r["11"].Candidates) != 1 || r["11"].Fanout != 1 {
		t.Fatalf("limit not applied: %+v", r["11"])
	}

	files, err := s.PackageFiles(ctx, id)
	if err != nil || len(files) != 3 {
		t.Fatalf("PackageFiles = %v %v", files, err)
	}
	st, err := s.Stats(ctx)
	if err != nil || st.Packages != 2 || st.Hashes != 2 || len(st.Coverage) != 2 {
		t.Fatalf("Stats = %+v %v", st, err)
	}
}

func TestPURLEpochAndArchAll(t *testing.T) {
	got := PURL(Candidate{Name: "perl-base", Version: "1:5.38.2-3", Arch: "all", Source: "perl", SourceVersion: "5.38.2-3", Distro: "debian", DistroVersion: "13"})
	want := "pkg:deb/debian/perl-base@1%3A5.38.2-3?arch=all&upstream=perl%405.38.2-3&distro=debian-13"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
