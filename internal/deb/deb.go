// Package deb reads a Debian binary package (.deb) as a stream and returns
// its control metadata and a sha256 for every file it ships.
//
// A .deb is an ar(1) archive with three members, in this order:
//
//	debian-binary            format version ("2.0\n")
//	control.tar[.gz|.xz|.zst] package metadata (control, conffiles, md5sums, scripts)
//	data.tar[.gz|.xz|.zst|.bz2] the files installed on disk
//
// Because control comes before data, the whole package can be processed in a
// single pass straight from an HTTP body, with nothing written to disk.
package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/jd869/debhash/internal/decompress"
)

// Kind is the type of a filesystem entry shipped by a package.
type Kind string

const (
	KindFile     Kind = "file"
	KindSymlink  Kind = "symlink"
	KindHardlink Kind = "hardlink"
)

// Entry is one non-directory entry from data.tar.
type Entry struct {
	Path       string // absolute, cleaned: /usr/lib/aarch64-linux-gnu/libc.so.6
	Kind       Kind
	SHA256     string // hex; set for files and hardlinks
	Size       int64
	LinkTarget string // raw symlink target, or the absolute path a hardlink points to
	Conffile   bool
}

// Control holds the fields of DEBIAN/control that we index.
type Control struct {
	Package       string
	Version       string
	Architecture  string
	Source        string // source package name; defaults to Package
	SourceVersion string // defaults to Version
	Fields        map[string]string
}

// Package is the parsed result of one .deb.
type Package struct {
	Control   Control
	Conffiles []string
	Entries   []Entry
}

const (
	arMagic     = "!<arch>\n"
	arHeaderLen = 60
)

// Read parses a .deb from r. It reads r to the end of the data member.
func Read(r io.Reader) (*Package, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	magic := make([]byte, len(arMagic))
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, fmt.Errorf("read ar magic: %w", err)
	}
	if string(magic) != arMagic {
		return nil, errors.New("not a .deb: bad ar magic")
	}

	pkg := &Package{}
	var sawControl, sawData bool
	hdr := make([]byte, arHeaderLen)
	for !sawData {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read ar header: %w", err)
		}
		if string(hdr[58:60]) != "`\n" {
			return nil, errors.New("corrupt ar header")
		}
		name := strings.TrimRight(strings.TrimSpace(string(hdr[0:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("ar member %q: bad size", name)
		}
		member := io.LimitReader(br, size)

		switch {
		case strings.HasPrefix(name, "control.tar"):
			if err := readControl(name, member, pkg); err != nil {
				return nil, err
			}
			sawControl = true
		case strings.HasPrefix(name, "data.tar"):
			if err := readData(name, member, pkg); err != nil {
				return nil, err
			}
			sawData = true
		}
		// Skip whatever the member reader left, plus ar's 2-byte alignment pad.
		if _, err := io.Copy(io.Discard, member); err != nil {
			return nil, fmt.Errorf("skip ar member %q: %w", name, err)
		}
		if size%2 == 1 && !sawData {
			if _, err := br.ReadByte(); err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
		}
	}
	if !sawControl {
		return nil, errors.New("no control.tar member")
	}
	if !sawData {
		return nil, errors.New("no data.tar member")
	}
	return pkg, nil
}

func readControl(name string, r io.Reader, pkg *Package) error {
	zr, err := decompress.Open(name, r)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch path.Clean("/" + h.Name) {
		case "/control":
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return err
			}
			pkg.Control = ParseControl(b)
		case "/conffiles":
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(b), "\n") {
				// Lines may carry a trailing " remove-on-upgrade" flag.
				if f := strings.Fields(line); len(f) > 0 {
					pkg.Conffiles = append(pkg.Conffiles, path.Clean(f[0]))
				}
			}
		}
	}
	if pkg.Control.Package == "" {
		return errors.New("control file has no Package field")
	}
	return nil
}

func readData(name string, r io.Reader, pkg *Package) error {
	zr, err := decompress.Open(name, r)
	if err != nil {
		return err
	}
	defer zr.Close()

	conf := make(map[string]bool, len(pkg.Conffiles))
	for _, c := range pkg.Conffiles {
		conf[c] = true
	}
	byPath := map[string]int{} // path -> index in Entries, for hardlinks
	buf := make([]byte, 256<<10)

	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		p := cleanTarPath(h.Name)
		if p == "/" {
			continue
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA appears in old debs
			hs := sha256.New()
			n, err := io.CopyBuffer(hs, tr, buf)
			if err != nil {
				return fmt.Errorf("hash %s: %w", p, err)
			}
			byPath[p] = len(pkg.Entries)
			pkg.Entries = append(pkg.Entries, Entry{
				Path: p, Kind: KindFile, SHA256: hex.EncodeToString(hs.Sum(nil)), Size: n, Conffile: conf[p],
			})
		case tar.TypeSymlink:
			pkg.Entries = append(pkg.Entries, Entry{Path: p, Kind: KindSymlink, LinkTarget: h.Linkname, Conffile: conf[p]})
		case tar.TypeLink:
			target := cleanTarPath(h.Linkname)
			e := Entry{Path: p, Kind: KindHardlink, LinkTarget: target, Conffile: conf[p]}
			if i, ok := byPath[target]; ok {
				e.SHA256, e.Size = pkg.Entries[i].SHA256, pkg.Entries[i].Size
			}
			pkg.Entries = append(pkg.Entries, e)
		}
	}
	return nil
}

func cleanTarPath(name string) string {
	return path.Clean("/" + strings.TrimPrefix(name, "./"))
}

// ParseControl parses an RFC 822-style control stanza. Continuation lines
// (starting with a space or tab) are appended to the previous field.
func ParseControl(b []byte) Control {
	fields := ParseStanza(string(b))
	c := Control{
		Package:      fields["Package"],
		Version:      fields["Version"],
		Architecture: fields["Architecture"],
		Fields:       fields,
	}
	c.Source, c.SourceVersion = SplitSource(fields["Source"], c.Package, c.Version)
	return c
}

// ParseStanza parses one deb822 paragraph into a field map.
func ParseStanza(s string) map[string]string {
	fields := map[string]string{}
	var last string
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" {
			fields[last] += "\n" + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		last = strings.TrimSpace(k)
		fields[last] = strings.TrimSpace(v)
	}
	return fields
}

// SplitSource turns a Source field ("glibc" or "glibc (2.39-0ubuntu8)") into
// a name and version, falling back to the binary package's own.
func SplitSource(field, pkg, version string) (string, string) {
	field = strings.TrimSpace(field)
	if field == "" {
		return pkg, version
	}
	name, rest, ok := strings.Cut(field, " ")
	if !ok {
		return name, version
	}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
		return name, strings.TrimSpace(rest[1 : len(rest)-1])
	}
	return name, version
}

// HashingReader tees everything read through a sha256, so a download can be
// verified against the digest published in the Packages index.
type HashingReader struct {
	r io.Reader
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
	n int64
}

// NewHashingReader wraps r.
func NewHashingReader(r io.Reader) *HashingReader {
	return &HashingReader{r: r, h: sha256.New()}
}

func (h *HashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if n > 0 {
		h.h.Write(p[:n])
		h.n += int64(n)
	}
	return n, err
}

// Drain reads the rest of the stream so the digest covers the whole file.
func (h *HashingReader) Drain() error {
	_, err := io.Copy(io.Discard, h)
	return err
}

// Sum returns the hex sha256 of everything read so far.
func (h *HashingReader) Sum() string { return hex.EncodeToString(h.h.Sum(nil)) }

// N returns the number of bytes read so far.
func (h *HashingReader) N() int64 { return h.n }

// ErrDigestMismatch is returned when a download does not match its index entry.
var ErrDigestMismatch = errors.New("sha256 mismatch")

// VerifyDigest compares got and want case-insensitively.
func VerifyDigest(got, want string) error {
	if !bytes.EqualFold([]byte(got), []byte(want)) {
		return fmt.Errorf("%w: got %s want %s", ErrDigestMismatch, got, want)
	}
	return nil
}
