package report

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/debtest"
	"github.com/jd869/debhash/internal/store"
)

func h(s string) string { return debtest.SHA256(s) }

func file(p, body string) deb.Entry {
	return deb.Entry{Path: p, Kind: deb.KindFile, SHA256: h(body)}
}

func TestBuild(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pub := store.Publication{Distro: "ubuntu", DistroVersion: "24.04", Suite: "noble-updates", Component: "main", Mirror: "m"}
	add := func(name, version string, entries ...deb.Entry) {
		t.Helper()
		meta := store.PackageMeta{DebSHA256: h(name + version), Name: name, Version: version, Arch: "arm64", Source: name, SourceVersion: version}
		if _, err := st.AddPackage(ctx, meta, pub, entries); err != nil {
			t.Fatal(err)
		}
	}
	// libc6 8.3 and 8.4 share an unchanged locale file; only libc.so.6 differs.
	add("libc6", "2.39-0ubuntu8.3", file("/usr/lib/aarch64-linux-gnu/libc.so.6", "libc 8.3"), file("/usr/share/i18n/C", "unchanged"))
	add("libc6", "2.39-0ubuntu8.4", file("/usr/lib/aarch64-linux-gnu/libc.so.6", "libc 8.4"), file("/usr/share/i18n/C", "unchanged"))
	add("base-files", "13ubuntu10.2", file("/usr/lib/os-release", "VERSION=24.04.2"))
	add("libpython3.12-stdlib", "3.12.3-1ubuntu0.5", file("/usr/lib/python3.12/abc.py", "abc source"))
	// Six packages ship the same licence text: high fan-out.
	for i := 0; i < 6; i++ {
		add(fmt.Sprintf("pkg%d", i), "1", file(fmt.Sprintf("/usr/share/doc/pkg%d/copyright", i), "GPL"))
	}

	files := []attest.File{
		{Path: "/lib/aarch64-linux-gnu/libc.so.6", SHA256: h("libc 8.4")},
		{Path: "/usr/share/i18n/C", SHA256: h("unchanged")},
		{Path: "/etc/os-release", SHA256: h("VERSION=24.04.2")},
		{Path: "/usr/share/doc/pkg0/copyright", SHA256: h("GPL")},
		{Path: "/usr/lib/python3.12/__pycache__/abc.cpython-312.pyc", SHA256: h("bytecode")},
		{Path: "/usr/lib/python3.12/__pycache__/gone.cpython-312.pyc", SHA256: h("bytecode2")},
		{Path: "/usr/lib/aarch64-linux-gnu/libunknown.so.1", SHA256: h("not indexed")},
		{Path: "/home/runner/work/x.so", SHA256: h("workspace")},
	}
	r, err := Build(ctx, st, files, store.Filter{Suite: "noble", Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Candidates != 5 || r.Hits != 4 || r.HighFanout != 1 || len(r.Misses) != 1 {
		t.Fatalf("counts: %+v", r)
	}
	if r.Distro == nil || r.Distro.Version != "13ubuntu10.2" || r.Distro.Release != "24.04" {
		t.Fatalf("distro = %+v", r.Distro)
	}
	if r.Pyc.Total != 2 || r.Pyc.ViaSource != 1 || r.Pyc.NoSourceIx != 1 {
		t.Fatalf("pyc = %+v", r.Pyc)
	}
	byName := map[string]Package{}
	for _, p := range r.Packages {
		byName[p.Name] = p
	}
	// The shared locale file allows 8.3 or 8.4; libc.so.6 narrows it to 8.4.
	libc := byName["libc6"]
	if len(libc.Versions) != 1 || libc.Versions[0] != "2.39-0ubuntu8.4" || libc.Files != 2 {
		t.Fatalf("libc6 = %+v", libc)
	}
	if !strings.Contains(libc.PURL, "libc6@2.39-0ubuntu8.4?arch=arm64") {
		t.Fatalf("purl = %s", libc.PURL)
	}
	// Both libc6 files are assigned to it, by hash.
	if len(libc.Matched) != 2 || libc.Matched[0].Evidence != EvidenceHash || libc.Matched[1].Path != "/usr/share/i18n/C" {
		t.Fatalf("libc6 matched files = %+v", libc.Matched)
	}
	// libpython3.12-stdlib has no hash hit, so it is not identified and the
	// .pyc has no package (with a version) to go to.
	if r.Pyc.Assigned != 0 {
		t.Fatalf("pyc assigned = %d", r.Pyc.Assigned)
	}
	// High fan-out licence must not invent pkg0..pkg5.
	if _, ok := byName["pkg0"]; ok {
		t.Fatal("high fan-out file created a package")
	}

	var buf bytes.Buffer
	r.WriteText(&buf, 10)
	for _, want := range []string{"Packages identified: 2", "libunknown.so.1", "ubuntu 24.04, base-files 13ubuntu10.2"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text report missing %q:\n%s", want, buf.String())
		}
	}
}

func TestSourceVersionPropagationAndGenerated(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pub := store.Publication{Distro: "ubuntu", DistroVersion: "24.04", Suite: "noble-updates", Component: "main", Mirror: "m"}
	add := func(name, version string, entries ...deb.Entry) {
		t.Helper()
		meta := store.PackageMeta{DebSHA256: h(name + version), Name: name, Version: version, Arch: "arm64", Source: "glibc", SourceVersion: version}
		if _, err := st.AddPackage(ctx, meta, pub, entries); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"2.39-0ubuntu8.3", "2.39-0ubuntu8.4"} {
		add("libc6", v, file("/usr/lib/aarch64-linux-gnu/libc.so.6", "libc "+v))
		add("libc6-dev", v, file("/usr/include/stdio.h", "unchanged header")) // identical in both
	}
	files := []attest.File{
		{Path: "/usr/lib/aarch64-linux-gnu/libc.so.6", SHA256: h("libc 2.39-0ubuntu8.4")},
		{Path: "/usr/include/stdio.h", SHA256: h("unchanged header")},
		{Path: "/etc/resolv.conf", SHA256: h("nameserver 127.0.0.53")},
	}
	r, err := Build(ctx, st, files, store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range r.Packages {
		byName[p.Name] = p
	}
	dev := byName["libc6-dev"]
	if len(dev.Versions) != 1 || dev.Versions[0] != "2.39-0ubuntu8.4" || dev.PinnedVia != "libc6" {
		t.Fatalf("libc6-dev should be pinned via libc6: %+v", dev)
	}
	if len(r.Misses) != 1 || !r.Misses[0].Generated {
		t.Fatalf("resolv.conf should be a generated miss: %+v", r.Misses)
	}
}

// The installed libc6 (v3) is not indexed. Its copyright happens to equal
// v2's, so hash intersection alone would answer "exactly v2". But v2 ships
// libc.so.6 with a different hash than the attested one: v2 is contradicted
// and no version must be claimed.
func TestConflictWhenInstalledVersionMissing(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pub := store.Publication{Distro: "ubuntu", DistroVersion: "22.04", Suite: "jammy", Component: "main", Mirror: "m"}
	for _, v := range []struct{ version, lib, doc string }{{"1", "libc v1", "doc v1"}, {"2", "libc v2", "doc v2+v3"}} {
		meta := store.PackageMeta{DebSHA256: h("libc" + v.version), Name: "libc6", Version: v.version, Arch: "amd64", Source: "glibc", SourceVersion: v.version}
		if _, err := st.AddPackage(ctx, meta, pub, []deb.Entry{
			file("/lib/x86_64-linux-gnu/libc.so.6", v.lib),
			{Path: "/lib/x86_64-linux-gnu/libc.so", Kind: deb.KindSymlink, LinkTarget: "libc.so.6"},
			file("/usr/share/doc/libc6/changelog.gz", v.doc),
			file("/etc/ld.so.conf.d/libc.conf", "conf"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	installedV3 := []attest.File{
		{Path: "/usr/lib/x86_64-linux-gnu/libc.so", SHA256: h("libc v3")}, // through the symlink
		{Path: "/usr/share/doc/libc6/changelog.gz", SHA256: h("doc v2+v3")},
		{Path: "/etc/ld.so.conf.d/libc.conf", SHA256: h("edited locally")}, // /etc: never a conflict
	}
	r, err := Build(ctx, st, installedV3, store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 1 {
		t.Fatalf("packages = %+v", r.Packages)
	}
	p := r.Packages[0]
	if p.Exact || p.Confidence != "conflict" || len(p.Conflicts) != 1 || p.Conflicts[0] != "/usr/lib/x86_64-linux-gnu/libc.so" {
		t.Fatalf("want conflict on libc.so, got %+v", p)
	}
	if strings.Contains(p.PURL, "@") {
		t.Fatalf("a contradicted package must not carry a version: %s", p.PURL)
	}

	// The same query for the indexed v2 is exact, and /etc edits don't matter.
	installedV2 := []attest.File{
		{Path: "/lib/x86_64-linux-gnu/libc.so.6", SHA256: h("libc v2")},
		{Path: "/usr/share/doc/libc6/changelog.gz", SHA256: h("doc v2+v3")},
		{Path: "/etc/ld.so.conf.d/libc.conf", SHA256: h("edited locally")},
	}
	r, err = Build(ctx, st, installedV2, store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Packages[0]; !p.Exact || p.Confidence != "exact" || p.Versions[0] != "2" {
		t.Fatalf("want exact v2, got %+v", p)
	}
}
