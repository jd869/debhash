// Package attest pulls (absolute path, sha256) pairs out of a witness
// attestation, for targeted ingestion and hit-rate measurement.
//
// It deliberately does not depend on sbomit: it walks the decoded in-toto
// statement and collects every absolute-path key whose value carries a sha256,
// which covers witness's material, product and command-run (openedfiles)
// attestors.
package attest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// File is one attested file.
type File struct {
	Path   string // absolute, cleaned
	SHA256 string // lower-case hex
}

// ReadFile parses a witness DSSE envelope or a bare in-toto statement.
func ReadFile(name string) ([]File, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse extracts files from envelope or statement JSON.
func Parse(b []byte) ([]File, error) {
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}
	if m, ok := doc.(map[string]any); ok {
		if p, ok := m["payload"].(string); ok {
			raw, err := base64.StdEncoding.DecodeString(p)
			if err != nil {
				return nil, fmt.Errorf("decode DSSE payload: %w", err)
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, fmt.Errorf("parse DSSE payload: %w", err)
			}
		}
	}
	found := map[string]string{}
	walk(doc, found)
	out := make([]File, 0, len(found))
	for p, h := range found {
		out = append(out, File{Path: p, SHA256: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func walk(v any, found map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if strings.HasPrefix(k, "/") {
				if h := sha256Of(child); h != "" {
					// Keep the first non-empty digest seen for a path.
					p := path.Clean(k)
					if _, dup := found[p]; !dup {
						found[p] = h
					}
				}
			}
			walk(child, found)
		}
	case []any:
		for _, child := range t {
			walk(child, found)
		}
	}
}

// emptySHA256 is the digest of zero bytes; witness records it for files it
// could not read, and it would match every empty file in every package.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func sha256Of(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if d, ok := m["digest"].(map[string]any); ok { // product attestor shape
		m = d
	}
	h, _ := m["sha256"].(string)
	h = strings.ToLower(strings.TrimSpace(h))
	if len(h) != 64 || h == emptySHA256 {
		return ""
	}
	return h
}

// Variants returns the paths under which p may appear in a package. On
// merged-/usr systems /lib, /bin and /sbin are symlinks into /usr, but
// packages may ship either spelling, so both are tried.
func Variants(p string) []string {
	p = path.Clean(p)
	out := []string{p}
	for _, pair := range [][2]string{{"/lib/", "/usr/lib/"}, {"/lib64/", "/usr/lib64/"}, {"/bin/", "/usr/bin/"}, {"/sbin/", "/usr/sbin/"}} {
		if strings.HasPrefix(p, pair[0]) {
			out = append(out, pair[1]+strings.TrimPrefix(p, pair[0]))
		} else if strings.HasPrefix(p, pair[1]) {
			out = append(out, pair[0]+strings.TrimPrefix(p, pair[1]))
		}
	}
	return out
}

// Category groups attested files for reporting.
type Category string

const (
	CatSharedLib Category = "shared-lib"
	CatBinary    Category = "binary"
	CatConfig    Category = "etc"
	CatHeader    Category = "header"
	CatPyc       Category = "pyc"
	CatPython    Category = "python-src"
	CatOther     Category = "other"
	CatNotSystem Category = "not-system"
)

// Classify says whether p could come from a distro package and what kind of
// file it is. Files under /usr/local, /home, /tmp, /opt, build workspaces and
// virtualenvs are never installed by dpkg.
func Classify(p string) Category {
	sys := false
	for _, pre := range []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/"} {
		if strings.HasPrefix(p, pre) {
			sys = true
			break
		}
	}
	if !sys || strings.HasPrefix(p, "/usr/local/") {
		return CatNotSystem
	}
	base := path.Base(p)
	switch {
	case strings.HasSuffix(p, ".pyc"):
		return CatPyc
	case strings.HasSuffix(p, ".py"):
		return CatPython
	case strings.HasPrefix(p, "/etc/"):
		return CatConfig
	case strings.Contains(p, "/include/") || strings.HasSuffix(p, ".h"):
		return CatHeader
	case strings.HasSuffix(base, ".so") || strings.Contains(base, ".so."):
		return CatSharedLib
	case strings.Contains(p, "/bin/") || strings.Contains(p, "/sbin/") || strings.Contains(p, "/libexec/"):
		return CatBinary
	}
	return CatOther
}

// PycSource maps a CPython bytecode cache path to its source file:
// /usr/lib/python3.12/__pycache__/abc.cpython-312.pyc -> /usr/lib/python3.12/abc.py
// (and abc.cpython-312.opt-1.pyc likewise). ok is false for other paths.
func PycSource(p string) (string, bool) {
	dir, base := path.Split(p)
	if path.Base(dir) != "__pycache__" || !strings.HasSuffix(base, ".pyc") {
		return "", false
	}
	mod, _, ok := strings.Cut(base, ".cpython-")
	if !ok {
		return "", false
	}
	return path.Join(path.Dir(path.Clean(dir)), mod+".py"), true
}
