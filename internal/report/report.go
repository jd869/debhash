// Package report measures how much of an attestation the index can attribute,
// and previews the attribution logic the sbomit client will use:
//
//  1. distro detection from the hash of /etc/os-release (shipped by base-files);
//  2. per file, look the sha256 up; a file whose candidates all name one
//     package is an "anchor" for it;
//  3. per package, intersect the versions allowed by each of its files: if one
//     version survives, the package version is exact;
//  4. high-fanout files (shipped by many packages) never identify a package on
//     their own;
//  5. generated __pycache__/*.pyc map to their .py source by path.
package report

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/store"
)

// HighFanout is the number of distinct packages above which a file is not
// trusted to identify a package by itself.
const HighFanout = 5

// Report is the outcome of measuring one attestation.
type Report struct {
	Filter       store.Filter              `json:"filter"`
	Attested     int                       `json:"attested_with_sha256"`
	ByCategory   map[attest.Category]*Stat `json:"by_category"`
	Candidates   int                       `json:"hash_candidates"` // system, non-.pyc files
	Hits         int                       `json:"hits"`
	Anchors      int                       `json:"anchors"`       // hits naming exactly one package
	HighFanout   int                       `json:"high_fanout"`   // hits shared by > HighFanout packages
	ExactVersion int                       `json:"exact_version"` // hits pinning one (name, version, arch)
	Pyc          PycStat                   `json:"pyc"`
	Distro       *Distro                   `json:"distro,omitempty"`
	Packages     []Package                 `json:"packages"`
	Misses       []Miss                    `json:"misses"`
}

// Stat counts per file category.
type Stat struct {
	Total int `json:"total"`
	Hits  int `json:"hits"`
}

// PycStat counts bytecode files and how many were attributed via their source.
type PycStat struct {
	Total      int `json:"total"`
	ViaSource  int `json:"attributed_via_source"`
	NoSourceIx int `json:"source_not_indexed"`
}

// Distro is what /etc/os-release resolved to.
type Distro struct {
	Package string `json:"package"`
	Version string `json:"version"`
	Distro  string `json:"distro"`
	Release string `json:"release"`
	Suite   string `json:"suite"`
}

// Package is one package identified from hashes.
type Package struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"` // surviving versions; exactly one = pinned
	Arch     string   `json:"arch"`
	Files    int      `json:"files"`   // attested files attributed by hash
	Anchors  int      `json:"anchors"` // of those, unique to this package
	PURL     string   `json:"purl,omitempty"`
	// PinnedVia names the sibling binary (same source package) whose exact
	// version narrowed this one, when its own files were ambiguous.
	PinnedVia string `json:"pinned_via,omitempty"`
}

// Miss is an attested system file not found in the index.
type Miss struct {
	Path     string          `json:"path"`
	Category attest.Category `json:"category"`
	// Generated is true for files written on the machine (by maintainer
	// scripts or at runtime) that no .deb contains, so no index can match.
	Generated bool `json:"generated,omitempty"`
}

// generatedFiles are created on the system, not shipped in any package.
var generatedFiles = map[string]bool{
	"/etc/hosts": true, "/etc/hostname": true, "/etc/resolv.conf": true, "/etc/machine-id": true,
	"/etc/ld.so.cache": true, "/etc/localtime": true, "/etc/timezone": true, "/etc/mtab": true,
	"/etc/passwd": true, "/etc/group": true, "/etc/shadow": true, "/etc/gshadow": true,
	"/etc/ssl/certs/ca-certificates.crt": true, // update-ca-certificates
	"/usr/lib/ssl/cert.pem":              true, // symlink to the bundle above
}

// Build measures files against the store.
func Build(ctx context.Context, st *store.Store, files []attest.File, f store.Filter) (*Report, error) {
	r := &Report{Filter: f, Attested: len(files), ByCategory: map[attest.Category]*Stat{}}
	cat := map[string]attest.Category{}
	var hashes []string
	var pycs []attest.File
	for _, file := range files {
		c := attest.Classify(file.Path)
		cat[file.Path] = c
		s := r.ByCategory[c]
		if s == nil {
			s = &Stat{}
			r.ByCategory[c] = s
		}
		s.Total++
		switch c {
		case attest.CatNotSystem:
		case attest.CatPyc:
			pycs = append(pycs, file)
		default:
			hashes = append(hashes, file.SHA256)
		}
	}
	r.Candidates = len(hashes)

	res, err := st.Lookup(ctx, hashes, f, 0)
	if err != nil {
		return nil, err
	}

	// Distro from os-release (base-files ships /usr/lib/os-release).
	for _, file := range files {
		if file.Path != "/etc/os-release" && file.Path != "/usr/lib/os-release" {
			continue
		}
		if hit := res[file.SHA256]; hit != nil {
			for _, c := range hit.Candidates {
				if c.Name == "base-files" {
					r.Distro = &Distro{Package: c.Name, Version: c.Version, Distro: c.Distro, Release: c.DistroVersion, Suite: c.Suite}
					break
				}
			}
		}
	}

	type agg struct {
		versions map[string]bool // nil until first file
		arch     string
		files    int
		anchors  int
		sample   store.Candidate
		source   string
		srcVer   map[string]string // binary version -> source version
	}
	pk := map[string]*agg{}
	for _, file := range files {
		c := cat[file.Path]
		if c == attest.CatNotSystem || c == attest.CatPyc {
			continue
		}
		hit := res[file.SHA256]
		if hit == nil {
			r.Misses = append(r.Misses, Miss{Path: file.Path, Category: c, Generated: generatedFiles[file.Path]})
			continue
		}
		r.Hits++
		r.ByCategory[c].Hits++
		if hit.Fanout > HighFanout {
			r.HighFanout++
			continue // never identifies a package on its own
		}
		nv := map[string]bool{}
		perName := map[string]map[string]bool{}
		for _, cand := range hit.Candidates {
			nv[cand.Name+" "+cand.Version+" "+cand.Arch] = true
			if perName[cand.Name] == nil {
				perName[cand.Name] = map[string]bool{}
			}
			perName[cand.Name][cand.Version] = true
			a := pk[cand.Name]
			if a == nil {
				a = &agg{arch: cand.Arch, sample: cand, source: cand.Source, srcVer: map[string]string{}}
				pk[cand.Name] = a
			}
			a.srcVer[cand.Version] = cand.SourceVersion
		}
		if len(nv) == 1 {
			r.ExactVersion++
		}
		if hit.Fanout == 1 {
			r.Anchors++
		}
		for name, versions := range perName {
			a := pk[name]
			a.files++
			if hit.Fanout == 1 {
				a.anchors++
			}
			if a.versions == nil {
				a.versions = versions
				continue
			}
			// Intersect; if that empties the set the files disagree (e.g.
			// a partial upgrade), so keep the union rather than lose data.
			inter := map[string]bool{}
			for v := range a.versions {
				if versions[v] {
					inter[v] = true
				}
			}
			if len(inter) > 0 {
				a.versions = inter
			} else {
				for v := range versions {
					a.versions[v] = true
				}
			}
		}
	}

	// .pyc: attribute via the .py source path.
	r.Pyc.Total = len(pycs)
	if len(pycs) > 0 {
		var srcs []string
		srcOf := map[string]string{}
		for _, p := range pycs {
			if s, ok := attest.PycSource(p.Path); ok {
				srcs = append(srcs, s)
				srcOf[p.Path] = s
			}
		}
		owners, err := st.LookupPaths(ctx, srcs, f)
		if err != nil {
			return nil, err
		}
		for _, p := range pycs {
			if len(owners[srcOf[p.Path]]) > 0 {
				r.Pyc.ViaSource++
			} else {
				r.Pyc.NoSourceIx++
			}
		}
	}

	// Source-version propagation: binaries built from one source package are
	// installed in lockstep (libc6-dev Depends: libc6 (= ${binary:Version})).
	// Headers and docs rarely change between versions, so libc6-dev alone is
	// ambiguous; once a rebuilt binary pins libc6, pin its siblings too.
	pinnedVia := map[string]string{}
	for changed := true; changed; {
		changed = false
		for name, a := range pk {
			if a.anchors == 0 || len(a.versions) != 1 {
				continue
			}
			var v string
			for k := range a.versions {
				v = k
			}
			sv := a.srcVer[v]
			for other, b := range pk {
				if other == name || b.source != a.source || len(b.versions) <= 1 {
					continue
				}
				keep := map[string]bool{}
				for bv := range b.versions {
					if b.srcVer[bv] == sv {
						keep[bv] = true
					}
				}
				if len(keep) > 0 && len(keep) < len(b.versions) {
					b.versions = keep
					pinnedVia[other] = name
					changed = true
				}
			}
		}
	}

	for name, a := range pk {
		// Only report packages backed by at least one anchor: a file shared
		// by a few packages must not invent the ones that are not installed.
		if a.anchors == 0 {
			continue
		}
		p := Package{Name: name, Arch: a.arch, Files: a.files, Anchors: a.anchors, PinnedVia: pinnedVia[name]}
		for v := range a.versions {
			p.Versions = append(p.Versions, v)
		}
		sort.Strings(p.Versions)
		if len(p.Versions) == 1 {
			c := a.sample
			c.Version = p.Versions[0]
			p.PURL = store.PURL(c)
		}
		r.Packages = append(r.Packages, p)
	}
	sort.Slice(r.Packages, func(i, j int) bool { return r.Packages[i].Name < r.Packages[j].Name })
	sort.Slice(r.Misses, func(i, j int) bool {
		if r.Misses[i].Category != r.Misses[j].Category {
			return r.Misses[i].Category < r.Misses[j].Category
		}
		return r.Misses[i].Path < r.Misses[j].Path
	})
	return r, nil
}

// WriteText prints a human-readable summary.
func (r *Report) WriteText(w io.Writer, maxMisses int) {
	pct := func(a, b int) string {
		if b == 0 {
			return "-"
		}
		return fmt.Sprintf("%.0f%%", 100*float64(a)/float64(b))
	}
	fmt.Fprintf(w, "Attested files with sha256: %d\n", r.Attested)
	fmt.Fprintf(w, "Filter: distro=%q suite=%q arch=%q\n\n", r.Filter.Distro, r.Filter.Suite, r.Filter.Arch)

	fmt.Fprintf(w, "%-12s %7s %7s %6s\n", "category", "files", "hits", "rate")
	cats := make([]string, 0, len(r.ByCategory))
	for c := range r.ByCategory {
		cats = append(cats, string(c))
	}
	sort.Strings(cats)
	for _, c := range cats {
		s := r.ByCategory[attest.Category(c)]
		hits := fmt.Sprint(s.Hits)
		rate := pct(s.Hits, s.Total)
		if c == string(attest.CatNotSystem) || c == string(attest.CatPyc) {
			hits, rate = "n/a", "n/a"
		}
		fmt.Fprintf(w, "%-12s %7d %7s %6s\n", c, s.Total, hits, rate)
	}
	fmt.Fprintf(w, "\nHash lookup candidates (system files, excluding .pyc): %d\n", r.Candidates)
	fmt.Fprintf(w, "  hits:            %d (%s)\n", r.Hits, pct(r.Hits, r.Candidates))
	fmt.Fprintf(w, "  anchors:         %d (unique to one package)\n", r.Anchors)
	fmt.Fprintf(w, "  exact version:   %d (one name+version+arch)\n", r.ExactVersion)
	fmt.Fprintf(w, "  high fan-out:    %d (> %d packages; not used to identify)\n", r.HighFanout, HighFanout)
	fmt.Fprintf(w, ".pyc files: %d, attributed via .py source: %d, source not indexed: %d\n", r.Pyc.Total, r.Pyc.ViaSource, r.Pyc.NoSourceIx)
	if r.Distro != nil {
		fmt.Fprintf(w, "Distro (from /etc/os-release hash): %s %s, base-files %s (%s)\n", r.Distro.Distro, r.Distro.Release, r.Distro.Version, r.Distro.Suite)
	} else {
		fmt.Fprintf(w, "Distro: /etc/os-release hash not in index\n")
	}

	pinned := 0
	for _, p := range r.Packages {
		if len(p.Versions) == 1 {
			pinned++
		}
	}
	fmt.Fprintf(w, "\nPackages identified: %d (%d with an exact version)\n", len(r.Packages), pinned)
	for _, p := range r.Packages {
		v := strings.Join(p.Versions, " | ")
		if len(p.Versions) > 3 {
			v = fmt.Sprintf("%d candidate versions", len(p.Versions))
		}
		via := ""
		if p.PinnedVia != "" {
			via = " (pinned via " + p.PinnedVia + ")"
		}
		fmt.Fprintf(w, "  %-32s %-28s files=%-3d anchors=%d%s\n", p.Name, v, p.Files, p.Anchors, via)
	}
	if len(r.Misses) > 0 {
		gen := 0
		for _, m := range r.Misses {
			if m.Generated {
				gen++
			}
		}
		fmt.Fprintf(w, "\nMisses: %d (%d generated on the machine, in no .deb; %d not in index)", len(r.Misses), gen, len(r.Misses)-gen)
		if maxMisses > 0 && len(r.Misses) > maxMisses {
			fmt.Fprintf(w, " (first %d)", maxMisses)
		}
		fmt.Fprintln(w)
		for i, m := range r.Misses {
			if maxMisses > 0 && i >= maxMisses {
				break
			}
			mark := ""
			if m.Generated {
				mark = "  [generated]"
			}
			fmt.Fprintf(w, "  %-11s %s%s\n", m.Category, m.Path, mark)
		}
	}
}
