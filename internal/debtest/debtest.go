// Package debtest builds small but real .deb files in memory for tests.
package debtest

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// File is one entry of data.tar. Exactly one of Body, Link or Hardlink is used.
type File struct {
	Path     string // tar name, e.g. "./usr/bin/foo"
	Body     string
	Link     string // symlink target
	Hardlink string // tar name of an earlier entry
}

// Spec describes a .deb to build.
type Spec struct {
	Control     string
	Conffiles   string
	Compression string // "", ".gz", ".xz" or ".zst"; used for both tar members
	Files       []File
}

// Build returns the bytes of a .deb matching spec.
func Build(t testing.TB, s Spec) []byte {
	t.Helper()
	control := tarball(t, s.Compression, func(tw *tar.Writer) {
		writeFile(t, tw, "./control", s.Control)
		if s.Conffiles != "" {
			writeFile(t, tw, "./conffiles", s.Conffiles)
		}
	})
	data := tarball(t, s.Compression, func(tw *tar.Writer) {
		// One directory entry is enough to check that directories are skipped.
		must(t, tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}))
		for _, f := range s.Files {
			switch {
			case f.Link != "":
				must(t, tw.WriteHeader(&tar.Header{Name: f.Path, Typeflag: tar.TypeSymlink, Linkname: f.Link, Mode: 0o777}))
			case f.Hardlink != "":
				must(t, tw.WriteHeader(&tar.Header{Name: f.Path, Typeflag: tar.TypeLink, Linkname: f.Hardlink, Mode: 0o755}))
			default:
				writeFile(t, tw, f.Path, f.Body)
			}
		}
	})

	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	arMember(&out, "debian-binary", []byte("2.0\n"))
	arMember(&out, "control.tar"+s.Compression, control)
	arMember(&out, "data.tar"+s.Compression, data)
	return out.Bytes()
}

// Reader returns a fresh reader over b.
func Reader(b []byte) io.Reader { return bytes.NewReader(b) }

// SHA256 returns the hex sha256 of s.
func SHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SHA256Bytes returns the hex sha256 of b.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Gzip compresses b.
func Gzip(t testing.TB, b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	must(t, err)
	must(t, zw.Close())
	return buf.Bytes()
}

// XZ compresses b.
func XZ(t testing.TB, b []byte) []byte {
	var buf bytes.Buffer
	zw, err := xz.NewWriter(&buf)
	must(t, err)
	_, err = zw.Write(b)
	must(t, err)
	must(t, zw.Close())
	return buf.Bytes()
}

func tarball(t testing.TB, comp string, fill func(*tar.Writer)) []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	fill(tw)
	must(t, tw.Close())
	switch comp {
	case "":
		return raw.Bytes()
	case ".gz":
		return Gzip(t, raw.Bytes())
	case ".xz":
		return XZ(t, raw.Bytes())
	case ".zst":
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf)
		must(t, err)
		_, err = zw.Write(raw.Bytes())
		must(t, err)
		must(t, zw.Close())
		return buf.Bytes()
	}
	t.Fatalf("unknown compression %q", comp)
	return nil
}

func writeFile(t testing.TB, tw *tar.Writer, name, body string) {
	must(t, tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}))
	_, err := tw.Write([]byte(body))
	must(t, err)
}

// arMember writes one ar member with a 60-byte header and 2-byte alignment.
// An odd-length member exercises the reader's padding logic.
func arMember(out *bytes.Buffer, name string, body []byte) {
	fmt.Fprintf(out, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(body))
	out.Write(body)
	if len(body)%2 == 1 {
		out.WriteByte('\n')
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
