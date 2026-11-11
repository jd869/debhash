// Package ingest downloads .deb files from an APT repository, hashes every
// file inside them and records the result in the store.
//
// Two selection modes:
//
//   - targeted: given paths from an attestation, use the Contents index
//     (path → package, the same data apt-file uses) to fetch only the packages
//     that ship one of those paths, in every version the pockets list;
//   - all: every package in the selected pockets/components.
//
// Historical versions come from pointing Mirror at a snapshot service
// (https://snapshot.ubuntu.com/ubuntu-ports/<timestamp>) and running again;
// debs already stored are recognised by their sha256 and only gain a
// publication row, so repeated snapshot runs cost only the new versions.
package ingest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jd869/debhash/internal/archive"
	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/launchpad"
	"github.com/jd869/debhash/internal/store"
)

// Options configures one ingest run.
type Options struct {
	Mirror     string
	Distro     string   // override; defaults to the Release Origin, lower-cased
	Suite      string   // codename: noble
	Pockets    []string // "release", "updates", "security", "backports", "proposed"
	Components []string // main, universe, ...
	Arch       string   // arm64
	Targets    []string // absolute paths from an attestation (targeted mode)
	All        bool     // ingest every package (ignores Targets)
	Workers    int
	Client     *http.Client
	Log        io.Writer
	// History, when set, also ingests every version of the targeted packages
	// that Launchpad says was live in [After, Before]: the versions a build
	// at that time could have installed, which the live mirror no longer has.
	History *History
}

// History selects historical versions from Launchpad.
type History struct {
	Launchpad *launchpad.Client
	After     time.Time
	Before    time.Time
}

// Report summarises a run.
type Report struct {
	Indexes      int      // Packages indexes read
	Listed       int      // stanzas across those indexes
	Wanted       int      // package names selected
	TargetPaths  int      // distinct target paths asked for
	FoundPaths   int      // target paths some package ships (per Contents)
	UniqueDebs   int      // distinct .debs selected
	AlreadyHad   int      // of those, already in the store
	Downloaded   int      // newly ingested
	Bytes        int64    // bytes downloaded
	FilesIndexed int      // file entries written
	Failed       []string // debs that failed (with reason)
	HistoryDebs  int      // publications added from Launchpad history
	Duration     time.Duration
}

type pubDeb struct {
	stanza archive.Stanza
	pubs   []store.Publication
}

// Run executes an ingest.
func Run(ctx context.Context, st *store.Store, o Options) (*Report, error) {
	start := time.Now()
	if o.Workers <= 0 {
		o.Workers = 4
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if !o.All && len(o.Targets) == 0 {
		return nil, fmt.Errorf("nothing to ingest: pass target paths or select all")
	}
	if o.History != nil && o.All {
		return nil, fmt.Errorf("history needs targeted mode: full-suite history would download every version of everything")
	}
	repo := archive.Repo{Mirror: o.Mirror, Client: o.Client}
	rep := &Report{}

	// 1. Release + Packages for every pocket/component.
	var releases []*archive.Release
	var all []archive.Stanza
	pubFor := map[string]store.Publication{} // suite/component -> publication
	var distro, distroVer string
	for _, pocket := range o.Pockets {
		suite := o.Suite
		if pocket != "" && pocket != "release" {
			suite += "-" + pocket
		}
		rel, err := repo.Release(ctx, suite)
		if err != nil {
			return nil, fmt.Errorf("release %s: %w", suite, err)
		}
		releases = append(releases, rel)
		distro = o.Distro
		if distro == "" {
			distro = strings.ToLower(rel.Origin)
		}
		distroVer = distroVersion(distro, rel.Version)
		for _, comp := range o.Components {
			stanzas, err := repo.Packages(ctx, rel, comp, o.Arch)
			if err != nil {
				return nil, fmt.Errorf("packages %s/%s: %w", suite, comp, err)
			}
			rep.Indexes++
			fmt.Fprintf(o.Log, "index %s/%s/binary-%s: %d packages\n", suite, comp, o.Arch, len(stanzas))
			pubFor[suite+"/"+comp] = store.Publication{
				Distro: distro, DistroVersion: distroVer,
				Suite: suite, Component: comp, Mirror: strings.TrimRight(o.Mirror, "/"),
			}
			all = append(all, stanzas...)
		}
	}
	rep.Listed = len(all)

	// 2. Select package names.
	var wanted map[string]bool
	if !o.All {
		var err error
		wanted, err = targetPackages(ctx, repo, releases, o, rep)
		if err != nil {
			return nil, err
		}
		rep.Wanted = len(wanted)
	}

	// 2b. Historical versions of the wanted packages.
	if o.History != nil {
		hist, err := history(ctx, o, distro, wanted)
		if err != nil {
			return nil, err
		}
		rep.HistoryDebs = len(hist)
		all = append(all, hist...)
	}
	pubOf := func(s archive.Stanza) store.Publication {
		if p, ok := pubFor[s.Suite+"/"+s.Component]; ok && s.Mirror == "" {
			return p
		}
		return store.Publication{Distro: distro, DistroVersion: distroVer, Suite: s.Suite, Component: s.Component, Mirror: s.Mirror}
	}

	// 3. Unique debs, each with every place it is published.
	byDeb := map[string]*pubDeb{}
	var order []string
	for _, s := range all {
		if wanted != nil && !wanted[s.Package] {
			continue
		}
		if s.SHA256 == "" {
			continue
		}
		key := strings.ToLower(s.SHA256)
		pd := byDeb[key]
		if pd == nil {
			pd = &pubDeb{stanza: s}
			byDeb[key] = pd
			order = append(order, key)
		}
		pd.pubs = append(pd.pubs, pubOf(s))
	}
	if o.All {
		rep.Wanted = len(order)
	}
	rep.UniqueDebs = len(order)

	var todo []*pubDeb
	for _, key := range order {
		pd := byDeb[key]
		id, ok, err := st.PackageID(ctx, key)
		if err != nil {
			return nil, err
		}
		if !ok {
			todo = append(todo, pd)
			continue
		}
		rep.AlreadyHad++
		for _, pub := range pd.pubs {
			if err := st.AddPublication(ctx, id, pub); err != nil {
				return nil, err
			}
		}
	}
	fmt.Fprintf(o.Log, "selected %d debs (%d already indexed, %d to download)\n", len(order), rep.AlreadyHad, len(todo))

	// 4. Download + hash in parallel; one writer.
	type result struct {
		pd    *pubDeb
		pkg   *deb.Package
		bytes int64
		err   error
	}
	// Cancelling on return stops workers if the writer bails out early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan *pubDeb)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pd := range jobs {
				pkg, n, err := fetch(ctx, repo, pd.stanza)
				select {
				case results <- result{pd: pd, pkg: pkg, bytes: n, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, pd := range todo {
			select {
			case jobs <- pd:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	done := 0
	for r := range results {
		done++
		s := r.pd.stanza
		rep.Bytes += r.bytes
		if r.err != nil {
			rep.Failed = append(rep.Failed, fmt.Sprintf("%s %s: %v", s.Package, s.Version, r.err))
			fmt.Fprintf(o.Log, "[%d/%d] FAIL %s %s: %v\n", done, len(todo), s.Package, s.Version, r.err)
			continue
		}
		meta := store.PackageMeta{
			DebSHA256: s.SHA256, Name: s.Package, Version: s.Version, Arch: s.Architecture,
			Source: s.Source, SourceVersion: s.SourceVersion, Filename: s.Filename, Size: r.bytes,
		}
		if meta.Filename == "" {
			meta.Filename = s.URL
		}
		// Control is authoritative; Packages should agree, but trust the deb.
		if c := r.pkg.Control; c.Package != "" {
			meta.Name, meta.Version, meta.Arch = c.Package, c.Version, c.Architecture
			meta.Source, meta.SourceVersion = c.Source, c.SourceVersion
		}
		id, err := st.AddPackage(ctx, meta, r.pd.pubs[0], r.pkg.Entries)
		if err != nil {
			return nil, err
		}
		for _, pub := range r.pd.pubs[1:] {
			if err := st.AddPublication(ctx, id, pub); err != nil {
				return nil, err
			}
		}
		rep.Downloaded++
		rep.FilesIndexed += len(r.pkg.Entries)
		fmt.Fprintf(o.Log, "[%d/%d] %s %s (%s, %.1f MB, %d files)\n", done, len(todo), meta.Name, meta.Version,
			meta.Arch, float64(r.bytes)/1e6, len(r.pkg.Entries))
	}
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	rep.Duration = time.Since(start)
	return rep, nil
}

// fetch streams one .deb: download → verify sha256 → parse → hash entries.
func fetch(ctx context.Context, repo archive.Repo, s archive.Stanza) (*deb.Package, int64, error) {
	body, err := repo.OpenPool(ctx, s)
	if err != nil {
		return nil, 0, err
	}
	defer body.Close()
	hr := deb.NewHashingReader(body)
	pkg, err := deb.Read(hr)
	if err != nil {
		return nil, hr.N(), err
	}
	if err := hr.Drain(); err != nil {
		return nil, hr.N(), err
	}
	if err := deb.VerifyDigest(hr.Sum(), s.SHA256); err != nil {
		return nil, hr.N(), err
	}
	return pkg, hr.N(), nil
}

// targetPackages maps attested paths to the packages that ship them, using
// the Contents indexes of every pocket.
func targetPackages(ctx context.Context, repo archive.Repo, releases []*archive.Release, o Options, rep *Report) (map[string]bool, error) {
	want := map[string]string{} // variant path -> original target path
	targets := map[string]bool{}
	for _, t := range o.Targets {
		targets[t] = true
		for _, v := range attest.Variants(t) {
			want[v] = t
		}
	}
	rep.TargetPaths = len(targets)
	found := map[string]bool{}
	names := map[string]bool{}
	for _, rel := range releases {
		idx := archive.ContentsIndexes(rel, o.Arch)
		sort.Strings(idx)
		for _, index := range idx {
			fmt.Fprintf(o.Log, "scanning %s/%s for %d target paths\n", rel.Suite, index, len(targets))
			err := repo.Contents(ctx, rel, index,
				func(p string) bool { _, ok := want[p]; return ok },
				func(p string, pkgs []string) {
					found[want[p]] = true
					for _, n := range pkgs {
						names[n] = true
					}
				})
			if err != nil {
				return nil, err
			}
		}
	}
	rep.FoundPaths = len(found)
	return names, nil
}

// history asks Launchpad for every version of each wanted package that was
// live in the window, as stanzas that download from Launchpad.
func history(ctx context.Context, o Options, distro string, wanted map[string]bool) ([]archive.Stanza, error) {
	names := make([]string, 0, len(wanted))
	for n := range wanted {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(o.Log, "launchpad: versions of %d packages live between %s and %s\n",
		len(names), o.History.After.Format("2006-01-02"), o.History.Before.Format("2006-01-02"))

	type res struct {
		name string
		bins []launchpad.Binary
		err  error
	}
	jobs := make(chan string)
	results := make(chan res)
	var wg sync.WaitGroup
	for i := 0; i < min(o.Workers, 4); i++ { // be polite to the Launchpad API
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				bins, err := o.History.Launchpad.Window(ctx, distro, o.Suite, o.Arch, n, o.History.After, o.History.Before)
				select {
				case results <- res{n, bins, err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, n := range names {
			select {
			case jobs <- n:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	var out []archive.Stanza
	var errs []string
	var retry []string
	collect := func(r res) {
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.name, r.err))
			fmt.Fprintf(o.Log, "launchpad %s: %v\n", r.name, r.err)
			return
		}
		versions := map[string]bool{}
		for _, b := range r.bins {
			versions[b.Version] = true
			out = append(out, archive.Stanza{
				Package: b.Name, Version: b.Version, Architecture: b.Arch,
				Source: b.Source, SourceVersion: b.SourceVersion,
				SHA256: b.SHA256, Size: b.Size, URL: b.URL,
				Suite: launchpad.Suite(o.Suite, b.Pocket), Component: b.Component,
				Mirror: "https://launchpad.net",
			})
		}
		fmt.Fprintf(o.Log, "launchpad %s: %d versions in window\n", r.name, len(versions))
	}
	for r := range results {
		if r.err != nil {
			// One package failing should not lose the rest; try it again
			// once the first pass is over (outages are often brief).
			retry = append(retry, r.name)
			fmt.Fprintf(o.Log, "launchpad %s: %v (will retry)\n", r.name, r.err)
			continue
		}
		collect(r)
	}
	if len(retry) > 0 {
		sort.Strings(retry)
		fmt.Fprintf(o.Log, "launchpad: retrying %d packages\n", len(retry))
		for _, n := range retry {
			if ctx.Err() != nil {
				break
			}
			bins, err := o.History.Launchpad.Window(ctx, distro, o.Suite, o.Arch, n, o.History.After, o.History.Before)
			collect(res{n, bins, err})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(errs) == len(names) && len(names) > 0 {
		return nil, fmt.Errorf("launchpad: every lookup failed (first: %s)", errs[0])
	}
	if len(errs) > 0 {
		fmt.Fprintf(o.Log, "launchpad: %d of %d packages failed after retry\n", len(errs), len(names))
	}
	return out, nil
}

// distroVersion normalises the Release Version field to what goes in a PURL
// distro qualifier: Ubuntu keeps "24.04"; Debian uses the major ("12.7" → "12").
func distroVersion(distro, v string) string {
	if distro == "debian" {
		if major, _, ok := strings.Cut(v, "."); ok {
			return major
		}
	}
	return v
}
