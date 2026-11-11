package deb

import (
	"testing"

	"github.com/jd869/debhash/internal/debtest"
)

func TestReadAllCompressions(t *testing.T) {
	for _, comp := range []string{"", ".gz", ".xz", ".zst"} {
		t.Run("data.tar"+comp, func(t *testing.T) {
			raw := debtest.Build(t, debtest.Spec{
				Control:     "Package: libfoo1\nVersion: 1:2.3-1ubuntu4\nArchitecture: arm64\nSource: foo (2.3-1ubuntu4)\nDescription: test\n multi-line\n",
				Conffiles:   "/etc/foo.conf\n",
				Compression: comp,
				Files: []debtest.File{
					{Path: "./etc/foo.conf", Body: "key=value\n"},
					{Path: "./usr/lib/aarch64-linux-gnu/libfoo.so.1.0", Body: "ELF-ish bytes"},
					{Path: "./usr/lib/aarch64-linux-gnu/libfoo.so.1", Link: "libfoo.so.1.0"},
					{Path: "./usr/bin/foo-hard", Hardlink: "./usr/lib/aarch64-linux-gnu/libfoo.so.1.0"},
				},
			})
			pkg, err := Read(debtest.Reader(raw))
			if err != nil {
				t.Fatal(err)
			}
			c := pkg.Control
			if c.Package != "libfoo1" || c.Version != "1:2.3-1ubuntu4" || c.Architecture != "arm64" {
				t.Fatalf("control = %+v", c)
			}
			if c.Source != "foo" || c.SourceVersion != "2.3-1ubuntu4" {
				t.Fatalf("source = %q %q", c.Source, c.SourceVersion)
			}
			if got := c.Fields["Description"]; got != "test\nmulti-line" {
				t.Fatalf("continuation line not joined: %q", got)
			}

			byPath := map[string]Entry{}
			for _, e := range pkg.Entries {
				byPath[e.Path] = e
			}
			so := byPath["/usr/lib/aarch64-linux-gnu/libfoo.so.1.0"]
			if so.Kind != KindFile || so.SHA256 != debtest.SHA256("ELF-ish bytes") || so.Size != 13 {
				t.Fatalf("regular file entry = %+v", so)
			}
			if l := byPath["/usr/lib/aarch64-linux-gnu/libfoo.so.1"]; l.Kind != KindSymlink || l.LinkTarget != "libfoo.so.1.0" {
				t.Fatalf("symlink entry = %+v", l)
			}
			if h := byPath["/usr/bin/foo-hard"]; h.Kind != KindHardlink || h.SHA256 != so.SHA256 {
				t.Fatalf("hardlink should inherit target hash: %+v", h)
			}
			if !byPath["/etc/foo.conf"].Conffile || so.Conffile {
				t.Fatal("conffile flag wrong")
			}
			if len(pkg.Entries) != 4 {
				t.Fatalf("want 4 entries (directories skipped), got %d", len(pkg.Entries))
			}
		})
	}
}

func TestReadRejectsNonDeb(t *testing.T) {
	if _, err := Read(debtest.Reader([]byte("PK\x03\x04 not a deb"))); err == nil {
		t.Fatal("expected error")
	}
}

func TestSplitSource(t *testing.T) {
	cases := []struct{ field, name, ver string }{
		{"", "bin", "1.0"},
		{"glibc", "glibc", "1.0"},
		{"glibc (2.39-0ubuntu8)", "glibc", "2.39-0ubuntu8"},
	}
	for _, c := range cases {
		n, v := SplitSource(c.field, "bin", "1.0")
		if n != c.name || v != c.ver {
			t.Errorf("SplitSource(%q) = %q %q", c.field, n, v)
		}
	}
}

func TestHashingReaderVerify(t *testing.T) {
	h := NewHashingReader(debtest.Reader([]byte("abc")))
	if err := h.Drain(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(h.Sum(), debtest.SHA256("abc")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigest(h.Sum(), debtest.SHA256("abd")); err == nil {
		t.Fatal("expected mismatch")
	}
}
