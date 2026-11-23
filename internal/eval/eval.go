// Package eval measures whether attribution converges to the right package
// version, using cases where the right answer is known.
//
//   - Synthetic: every indexed deb is queried with (a subset of) its own
//     files. The deb's version is the right answer.
//   - Missing: the same, but the deb is hidden from the index first, so the
//     right answer is absent. Any exact answer is then an over-promise.
//   - Truth: a real system's files (or a witness attestation) compared with
//     that system's dpkg list.
package eval

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"path"
	"sort"
	"strings"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/report"
	"github.com/jd869/debhash/internal/store"
)

// Outcome classifies one query.
type Outcome string

const (
	// ExactCorrect: one version left, and it is the right one.
	ExactCorrect Outcome = "exact_correct"
	// Ambiguous: several versions left, the right one among them.
	Ambiguous Outcome = "ambiguous"
	// Wrong: the right version was ruled out (exact on another version, or
	// candidates that don't include it).
	Wrong Outcome = "wrong"
	// NotFound: the package was not identified at all.
	NotFound Outcome = "not_found"
	// Skipped: the strategy left no file to query.
	Skipped Outcome = "skipped"
)

// Strategy picks which of a deb's files a simulated build "touched".
type Strategy string

const (
	// StrategyAll queries every file of the deb.
	StrategyAll Strategy = "all"
	// StrategyBinaries queries only shared libraries and executables.
	StrategyBinaries Strategy = "binaries"
	// StrategyOne queries a single random file.
	StrategyOne Strategy = "one"
	// StrategyTouched queries the deb's files that a real build touched.
	StrategyTouched Strategy = "touched"
)

// Case is one evaluated query.
type Case struct {
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	Strategy   Strategy `json:"strategy"`
	Files      int      `json:"files"`
	Outcome    Outcome  `json:"outcome"`
	Candidates []string `json:"candidates,omitempty"`
}

// Summary aggregates cases of one strategy.
type Summary struct {
	Strategy     Strategy `json:"strategy"`
	Queries      int      `json:"queries"` // excludes skipped
	ExactCorrect int      `json:"exact_correct"`
	Ambiguous    int      `json:"ambiguous"`
	Wrong        int      `json:"wrong"`
	// ExactWrong are the wrong answers that named a single version: the
	// confident mistakes ("over-promises").
	ExactWrong int `json:"exact_wrong"`
	NotFound   int `json:"not_found"`
	Skipped    int `json:"skipped"`
	// MeanCandidates is the average candidate-set size of ambiguous answers.
	MeanCandidates float64 `json:"mean_candidates_when_ambiguous"`
}

// Options configures a synthetic or missing-data run.
type Options struct {
	Filter     store.Filter
	Strategies []Strategy
	Sample     int   // 0 = every deb
	Seed       int64 // for sampling and StrategyOne
	// Touched is the set of paths real builds opened (for StrategyTouched).
	Touched map[string]bool
}

// Synthetic queries every (sampled) deb with its own files.
func Synthetic(ctx context.Context, st *store.Store, o Options) ([]Summary, []Case, error) {
	return run(ctx, st, o, false)
}

// Missing queries every (sampled) deb with its own files while hiding that
// deb from the index. ExactCorrect cannot happen; an exact answer counts as
// Wrong and is the over-promise this test looks for.
func Missing(ctx context.Context, st *store.Store, o Options) ([]Summary, []Case, error) {
	return run(ctx, st, o, true)
}

func run(ctx context.Context, st *store.Store, o Options, hide bool) ([]Summary, []Case, error) {
	debs, err := st.Debs(ctx)
	if err != nil {
		return nil, nil, err
	}
	rng := rand.New(rand.NewSource(o.Seed))
	if o.Sample > 0 && o.Sample < len(debs) {
		rng.Shuffle(len(debs), func(i, j int) { debs[i], debs[j] = debs[j], debs[i] })
		debs = debs[:o.Sample]
		sort.Slice(debs, func(i, j int) bool { return debs[i].ID < debs[j].ID })
	}
	if len(o.Strategies) == 0 {
		o.Strategies = []Strategy{StrategyAll}
	}

	var cases []Case
	for _, d := range debs {
		manifest, err := st.PackageFiles(ctx, d.ID)
		if err != nil {
			return nil, nil, err
		}
		var own []attest.File
		links := map[string]string{} // symlink path -> absolute target
		for _, f := range manifest {
			if f.Kind == "symlink" && f.LinkTarget != "" {
				t := f.LinkTarget
				if !strings.HasPrefix(t, "/") {
					t = path.Join(path.Dir(f.Path), t)
				}
				links[f.Path] = path.Clean(t)
				continue
			}
			if f.SHA256 == "" || f.Kind == "symlink" {
				continue
			}
			c := attest.Classify(f.Path)
			if c == attest.CatNotSystem || c == attest.CatPyc {
				continue
			}
			own = append(own, attest.File{Path: f.Path, SHA256: f.SHA256})
		}
		for _, s := range o.Strategies {
			files := pick(s, own, links, o.Touched, rng)
			c := Case{Package: d.Name, Version: d.Version, Strategy: s, Files: len(files)}
			if len(files) == 0 {
				c.Outcome = Skipped
				cases = append(cases, c)
				continue
			}
			f := o.Filter
			if hide {
				f.ExcludePackageID = d.ID
			}
			r, err := report.Build(ctx, st, files, f)
			if err != nil {
				return nil, nil, err
			}
			c.Outcome, c.Candidates = score(r, d.Name, d.Version)
			cases = append(cases, c)
		}
	}
	return summarize(o.Strategies, cases), cases, nil
}

func pick(s Strategy, own []attest.File, links map[string]string, touched map[string]bool, rng *rand.Rand) []attest.File {
	switch s {
	case StrategyAll:
		return own
	case StrategyBinaries:
		var out []attest.File
		for _, f := range own {
			if c := attest.Classify(f.Path); c == attest.CatSharedLib || c == attest.CatBinary {
				out = append(out, f)
			}
		}
		return out
	case StrategyOne:
		if len(own) == 0 {
			return nil
		}
		return []attest.File{own[rng.Intn(len(own))]}
	case StrategyTouched:
		// A build opens libraries through their soname symlinks
		// (libcap.so.2 -> libcap.so.2.44), and witness hashes the target.
		// So a regular file counts as touched if it, or a symlink chain
		// ending at it, was opened.
		reached := map[string]bool{}
		for t := range touched {
			for _, p := range attest.Variants(t) {
				for hop := 0; hop < 4; hop++ {
					reached[p] = true
					next, ok := links[p]
					if !ok {
						break
					}
					p = next
				}
			}
		}
		var out []attest.File
		for _, f := range own {
			for _, v := range attest.Variants(f.Path) {
				if reached[v] {
					out = append(out, f)
					break
				}
			}
		}
		return out
	}
	return nil
}

// score finds the target package in a report and classifies the answer.
func score(r *report.Report, name, version string) (Outcome, []string) {
	for _, p := range r.Packages {
		if p.Name != name {
			continue
		}
		has := false
		for _, v := range p.Versions {
			if v == version {
				has = true
			}
		}
		switch {
		case p.Exact && has:
			return ExactCorrect, p.Versions
		case !p.Exact && has:
			return Ambiguous, p.Versions
		default:
			return Wrong, p.Versions
		}
	}
	return NotFound, nil
}

func summarize(strategies []Strategy, cases []Case) []Summary {
	var out []Summary
	for _, s := range strategies {
		sum := Summary{Strategy: s}
		cands := 0
		for _, c := range cases {
			if c.Strategy != s {
				continue
			}
			switch c.Outcome {
			case ExactCorrect:
				sum.ExactCorrect++
			case Ambiguous:
				sum.Ambiguous++
				cands += len(c.Candidates)
			case Wrong:
				sum.Wrong++
				if len(c.Candidates) == 1 {
					sum.ExactWrong++
				}
			case NotFound:
				sum.NotFound++
			case Skipped:
				sum.Skipped++
				continue
			}
			sum.Queries++
		}
		if sum.Ambiguous > 0 {
			sum.MeanCandidates = float64(cands) / float64(sum.Ambiguous)
		}
		out = append(out, sum)
	}
	return out
}

// WriteSummaries prints a table of summaries.
func WriteSummaries(w io.Writer, title string, sums []Summary) {
	pct := func(a, b int) string {
		if b == 0 {
			return "-"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
	}
	fmt.Fprintln(w, title)
	fmt.Fprintf(w, "%-9s %7s %15s %22s %13s %15s %13s %8s\n", "strategy", "queries", "exact+correct", "ambiguous (avg cands)", "wrong", "of which EXACT", "not found", "skipped")
	for _, s := range sums {
		fmt.Fprintf(w, "%-9s %7d %8d %6s %8d %6s (%4.1f) %6d %6s %8d %6s %6d %6s %8d\n", s.Strategy, s.Queries,
			s.ExactCorrect, pct(s.ExactCorrect, s.Queries),
			s.Ambiguous, pct(s.Ambiguous, s.Queries), s.MeanCandidates,
			s.Wrong, pct(s.Wrong, s.Queries),
			s.ExactWrong, pct(s.ExactWrong, s.Queries),
			s.NotFound, pct(s.NotFound, s.Queries), s.Skipped)
	}
}

// WriteWrong lists wrong answers (up to max), for investigation.
func WriteWrong(w io.Writer, cases []Case, max int) {
	n := 0
	for _, c := range cases {
		if c.Outcome != Wrong {
			continue
		}
		if n == 0 {
			fmt.Fprintln(w, "\nWrong answers:")
		}
		if max > 0 && n >= max {
			fmt.Fprintln(w, "  ...")
			return
		}
		fmt.Fprintf(w, "  [%s] %s %s -> %s\n", c.Strategy, c.Package, c.Version, strings.Join(c.Candidates, " | "))
		n++
	}
}

// TruthResult compares an attribution with a system's dpkg list.
type TruthResult struct {
	Installed    int `json:"installed"`
	Identified   int `json:"identified"`
	ExactCorrect int `json:"exact_correct"`
	Ambiguous    int `json:"ambiguous_correct_among_candidates"`
	// Wrong lists identified packages whose dpkg version was ruled out.
	Wrong []string `json:"wrong"`
	// NotInstalled lists identified packages dpkg doesn't list.
	NotInstalled []string `json:"not_installed"`
	// IndexGaps lists installed packages whose dpkg version is not indexed.
	IndexGaps []string `json:"index_gaps"`
	// Unidentified counts installed packages not identified (often simply
	// not touched by the build).
	Unidentified int `json:"unidentified"`
}

// Truth runs the attribution on files and checks it against dpkg
// (package name -> version).
func Truth(ctx context.Context, st *store.Store, files []attest.File, dpkg map[string]string, f store.Filter) (*TruthResult, error) {
	r, err := report.Build(ctx, st, files, f)
	if err != nil {
		return nil, err
	}
	indexed, err := st.Versions(ctx)
	if err != nil {
		return nil, err
	}
	tr := &TruthResult{Installed: len(dpkg), Identified: len(r.Packages), Wrong: []string{}, NotInstalled: []string{}, IndexGaps: []string{}}
	seen := map[string]bool{}
	for _, p := range r.Packages {
		seen[p.Name] = true
		want, ok := dpkg[p.Name]
		if !ok {
			tr.NotInstalled = append(tr.NotInstalled, p.Name)
			continue
		}
		switch o, _ := score(r, p.Name, want); o {
		case ExactCorrect:
			tr.ExactCorrect++
		case Ambiguous:
			tr.Ambiguous++
		default:
			tr.Wrong = append(tr.Wrong, fmt.Sprintf("%s: dpkg %s, got %s", p.Name, want, strings.Join(p.Versions, " | ")))
		}
	}
	for name, v := range dpkg {
		if !seen[name] {
			tr.Unidentified++
		}
		if !indexed[name][v] {
			tr.IndexGaps = append(tr.IndexGaps, name+" "+v)
		}
	}
	sort.Strings(tr.Wrong)
	sort.Strings(tr.NotInstalled)
	sort.Strings(tr.IndexGaps)
	return tr, nil
}

// ReadDpkg parses `dpkg-query -W -f '${Package}\t${Version}[\t${Architecture}]\n'`.
func ReadDpkg(r io.Reader) (map[string]string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) >= 2 && f[0] != "" && f[1] != "" {
			out[strings.SplitN(f[0], ":", 2)[0]] = f[1]
		}
	}
	return out, nil
}

// WriteTruth prints a TruthResult.
func WriteTruth(w io.Writer, label string, t *TruthResult) {
	fmt.Fprintf(w, "%s: %d installed, %d identified by hash\n", label, t.Installed, t.Identified)
	fmt.Fprintf(w, "  exact and correct:                 %d\n", t.ExactCorrect)
	fmt.Fprintf(w, "  ambiguous, right version included: %d\n", t.Ambiguous)
	fmt.Fprintf(w, "  WRONG version:                     %d\n", len(t.Wrong))
	for _, s := range t.Wrong {
		fmt.Fprintf(w, "    %s\n", s)
	}
	fmt.Fprintf(w, "  identified but not installed:      %d %v\n", len(t.NotInstalled), t.NotInstalled)
	fmt.Fprintf(w, "  installed, not identified:         %d\n", t.Unidentified)
	fmt.Fprintf(w, "  installed version not in index:    %d\n", len(t.IndexGaps))
	for _, s := range t.IndexGaps {
		fmt.Fprintf(w, "    %s\n", s)
	}
}
