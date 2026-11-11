// Package archive reads a Debian-format APT repository (Debian, Ubuntu, or a
// snapshot of either): the Release file, Packages indexes, Contents indexes and
// pool files.
//
// Every index we download is checked against the sha256 listed in Release, and
// every .deb is checked against the sha256 in Packages. The Release file's own
// GPG signature (InRelease) is NOT verified yet; that is a known gap for a
// production deployment.
package archive

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/decompress"
)

// Repo is one mirror base URL, e.g. http://ports.ubuntu.com/ubuntu-ports or
// https://snapshot.ubuntu.com/ubuntu-ports/20250101T000000Z.
type Repo struct {
	Mirror string
	Client *http.Client
}

// Release is a parsed dists/<suite>/Release file.
type Release struct {
	Suite   string // the directory name we fetched, e.g. noble-updates
	Origin  string // Ubuntu, Debian
	Version string // 24.04, 12.7
	Date    string
	Files   map[string]IndexFile // path relative to dists/<suite>/
}

// IndexFile is one entry of the Release SHA256 section.
type IndexFile struct {
	SHA256 string
	Size   int64
}

// Stanza is one paragraph of a Packages index.
type Stanza struct {
	Package, Version, Architecture, Source, SourceVersion string
	Filename, SHA256                                      string
	Size                                                  int64
	Suite, Component                                      string
}

// Get fetches mirror/rel, retrying transient failures.
func (r Repo) Get(ctx context.Context, rel string) (*http.Response, error) {
	url := strings.TrimRight(r.Mirror, "/") + "/" + strings.TrimLeft(rel, "/")
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "debhash/0.1")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
			resp.Body.Close()
			lastErr = fmt.Errorf("GET %s: %s", url, resp.Status)
			continue
		default:
			resp.Body.Close()
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
	}
	return nil, lastErr
}

// Release fetches and parses dists/<suite>/Release.
func (r Repo) Release(ctx context.Context, suite string) (*Release, error) {
	resp, err := r.Get(ctx, "dists/"+suite+"/Release")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	rel := ParseRelease(string(b))
	rel.Suite = suite
	return rel, nil
}

// ParseRelease parses the fields and the SHA256 file list of a Release file.
func ParseRelease(s string) *Release {
	rel := &Release{Files: map[string]IndexFile{}}
	inSHA := false
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' {
			if inSHA {
				f := strings.Fields(line)
				if len(f) == 3 {
					size, _ := strconv.ParseInt(f[1], 10, 64)
					rel.Files[f[2]] = IndexFile{SHA256: f[0], Size: size}
				}
			}
			continue
		}
		k, v, _ := strings.Cut(line, ":")
		v = strings.TrimSpace(v)
		inSHA = k == "SHA256"
		switch k {
		case "Origin":
			rel.Origin = v
		case "Version":
			rel.Version = v
		case "Date":
			rel.Date = v
		}
	}
	return rel
}

// openIndex downloads dists/<suite>/<rel>, verifies its Release digest while
// streaming, and returns a decompressed reader. Close checks the digest.
func (r Repo) openIndex(ctx context.Context, release *Release, rel string) (io.ReadCloser, error) {
	want, ok := release.Files[rel]
	if !ok {
		return nil, fmt.Errorf("%s not listed in %s/Release", rel, release.Suite)
	}
	resp, err := r.Get(ctx, "dists/"+release.Suite+"/"+rel)
	if err != nil {
		return nil, err
	}
	hr := deb.NewHashingReader(resp.Body)
	zr, err := decompress.Open(rel, hr)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	return &verifyingReader{ReadCloser: zr, body: resp.Body, hr: hr, want: want.SHA256, name: rel}, nil
}

type verifyingReader struct {
	io.ReadCloser
	body io.Closer
	hr   *deb.HashingReader
	want string
	name string
}

func (v *verifyingReader) Close() error {
	v.ReadCloser.Close()
	defer v.body.Close()
	if err := v.hr.Drain(); err != nil {
		return err
	}
	if err := deb.VerifyDigest(v.hr.Sum(), v.want); err != nil {
		return fmt.Errorf("%s: %w", v.name, err)
	}
	return nil
}

// pickIndex returns the best-compressed variant of base listed in Release.
func pickIndex(rel *Release, base string) (string, bool) {
	for _, ext := range []string{".xz", ".gz", ""} {
		if _, ok := rel.Files[base+ext]; ok {
			return base + ext, true
		}
	}
	return "", false
}

// Packages returns all stanzas of <component>/binary-<arch>/Packages.
func (r Repo) Packages(ctx context.Context, rel *Release, component, arch string) ([]Stanza, error) {
	name, ok := pickIndex(rel, component+"/binary-"+arch+"/Packages")
	if !ok {
		return nil, fmt.Errorf("no Packages index for %s/%s in %s", component, arch, rel.Suite)
	}
	rc, err := r.openIndex(ctx, rel, name)
	if err != nil {
		return nil, err
	}
	stanzas, perr := ParsePackages(rc, rel.Suite, component)
	if cerr := rc.Close(); cerr != nil {
		return nil, cerr
	}
	return stanzas, perr
}

// ParsePackages parses a Packages index stream.
func ParsePackages(r io.Reader, suite, component string) ([]Stanza, error) {
	var out []Stanza
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var para strings.Builder
	flush := func() {
		if para.Len() == 0 {
			return
		}
		f := deb.ParseStanza(para.String())
		para.Reset()
		if f["Package"] == "" || f["Filename"] == "" {
			return
		}
		size, _ := strconv.ParseInt(f["Size"], 10, 64)
		src, srcVer := deb.SplitSource(f["Source"], f["Package"], f["Version"])
		out = append(out, Stanza{
			Package: f["Package"], Version: f["Version"], Architecture: f["Architecture"],
			Source: src, SourceVersion: srcVer, Filename: f["Filename"], SHA256: f["SHA256"],
			Size: size, Suite: suite, Component: component,
		})
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		// Long Description fields are irrelevant and expensive to keep.
		para.WriteString(line)
		para.WriteByte('\n')
	}
	flush()
	return out, sc.Err()
}

// ContentsIndexes lists the Contents-<arch> indexes in a Release file. Ubuntu
// publishes one at the suite root; Debian publishes one per component.
func ContentsIndexes(rel *Release, arch string) []string {
	seen := map[string]bool{}
	var out []string
	for p := range rel.Files {
		dir, base := path.Split(p)
		for _, want := range []string{"Contents-" + arch, "Contents-all"} {
			if strings.HasPrefix(base, want) {
				variant, ok := pickIndex(rel, dir+want)
				if ok && !seen[variant] {
					seen[variant] = true
					out = append(out, variant)
				}
			}
		}
	}
	return out
}

// Contents streams the given Contents index and calls fn for every line whose
// path satisfies want. Paths are returned absolute ("/usr/bin/ls") and
// packages as bare names ("coreutils").
func (r Repo) Contents(ctx context.Context, rel *Release, index string, want func(string) bool, fn func(path string, pkgs []string)) error {
	rc, err := r.openIndex(ctx, rel, index)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		p, pkgs, ok := ParseContentsLine(sc.Text())
		if ok && want(p) {
			fn(p, pkgs)
		}
	}
	if err := sc.Err(); err != nil {
		rc.Close()
		return err
	}
	return rc.Close()
}

// ParseContentsLine splits "usr/bin/ls   utils/coreutils,admin/foo". The
// location list is the last whitespace-separated field; paths may contain
// spaces. Old-style "FILE  LOCATION" headers are skipped.
func ParseContentsLine(line string) (string, []string, bool) {
	line = strings.TrimRight(line, " \t\r")
	i := strings.LastIndexAny(line, " \t")
	if i <= 0 {
		return "", nil, false
	}
	p := strings.TrimRight(line[:i], " \t")
	locs := line[i+1:]
	if p == "FILE" && locs == "LOCATION" {
		return "", nil, false
	}
	var pkgs []string
	for _, loc := range strings.Split(locs, ",") {
		if j := strings.LastIndexByte(loc, '/'); j >= 0 {
			loc = loc[j+1:]
		}
		if loc != "" {
			pkgs = append(pkgs, loc)
		}
	}
	return path.Clean("/" + p), pkgs, len(pkgs) > 0
}

// OpenPool opens a pool file (a .deb) for streaming.
func (r Repo) OpenPool(ctx context.Context, filename string) (io.ReadCloser, error) {
	resp, err := r.Get(ctx, filename)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
