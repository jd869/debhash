// Command debhash builds and serves a file-hash → Debian package index.
//
//	debhash ingest  --db idx.db --mirror URL --suite noble --arch arm64 [--paths-from att.json | --all]
//	                [--history launchpad --history-after 2025-09-01 --history-before 2025-12-10]
//	debhash report  --db idx.db --attestation att.json [--suite noble --arch arm64] [--json]
//	debhash lookup  --db idx.db <sha256>...
//	debhash inspect file.deb
//	debhash serve   --db idx.db --addr :8080
//	debhash stats   --db idx.db
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/eval"
	"github.com/jd869/debhash/internal/ingest"
	"github.com/jd869/debhash/internal/keyring"
	"github.com/jd869/debhash/internal/launchpad"
	"github.com/jd869/debhash/internal/report"
	"github.com/jd869/debhash/internal/server"
	"github.com/jd869/debhash/internal/store"
)

const usage = `debhash: map file sha256 digests to Debian/Ubuntu packages

Commands:
  ingest   download .debs from a mirror and index every file's sha256
  report   measure how much of a witness attestation the index attributes
  eval     check that attribution converges to the right version (known answers)
  lookup   look up sha256 digests in the index
  inspect  hash the files inside a local .deb (no database)
  serve    serve the index over HTTP
  stats    show what the index covers

Run "debhash <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmds := map[string]func(context.Context, []string) error{
		"ingest": cmdIngest, "report": cmdReport, "lookup": cmdLookup,
		"inspect": cmdInspect, "serve": cmdServe, "stats": cmdStats, "eval": cmdEval,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(ctx, os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "debhash:", err)
		os.Exit(1)
	}
}

func openDB(path string) (*store.Store, error) {
	if path == "" {
		return nil, errors.New("--db is required")
	}
	return store.Open(path)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdIngest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	db := fs.String("db", "debhash.db", "SQLite database path")
	mirror := fs.String("mirror", "http://ports.ubuntu.com/ubuntu-ports", "mirror base URL (a snapshot URL ingests history)")
	distro := fs.String("distro", "", "distro name for PURLs (default: Release Origin, lower-cased)")
	suite := fs.String("suite", "noble", "release codename")
	pockets := fs.String("pockets", "release,updates,security", "comma-separated pockets")
	components := fs.String("components", "main,universe", "comma-separated components")
	arch := fs.String("arch", "arm64", "architecture")
	var pathsFrom stringList
	fs.Var(&pathsFrom, "paths-from", "witness attestation (or JSON of path -> sha256): only ingest packages shipping its files; repeatable")
	all := fs.Bool("all", false, "ingest every package in the selected pockets/components")
	workers := fs.Int("workers", 4, "parallel downloads")
	keyringPath := fs.String("keyring", "", "OpenPGP keyring that signs the archive (default: embedded Ubuntu archive keyring; e.g. /usr/share/keyrings/debian-archive-keyring.gpg for Debian)")
	noVerify := fs.Bool("no-verify", false, "do not verify Release signatures (only for test mirrors)")
	history := fs.String("history", "", `also ingest historical versions; "launchpad" (Ubuntu only)`)
	after := fs.String("history-after", "", "history window start, YYYY-MM-DD")
	before := fs.String("history-before", "", "history window end, YYYY-MM-DD (e.g. the build date)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := ingest.Options{
		Mirror: *mirror, Distro: *distro, Suite: *suite, Pockets: splitList(*pockets),
		Components: splitList(*components), Arch: *arch, All: *all, Workers: *workers,
		Client: &http.Client{Timeout: 10 * time.Minute}, Log: os.Stderr, NoVerify: *noVerify,
	}
	if !*noVerify {
		var err error
		if *keyringPath != "" {
			opts.Keyring, err = keyring.Load(*keyringPath)
		} else {
			opts.Keyring, err = keyring.Ubuntu()
		}
		if err != nil {
			return err
		}
	}
	switch *history {
	case "":
	case "launchpad":
		a, err := time.Parse("2006-01-02", *after)
		if err != nil {
			return fmt.Errorf("--history-after: want YYYY-MM-DD: %w", err)
		}
		b, err := time.Parse("2006-01-02", *before)
		if err != nil {
			return fmt.Errorf("--history-before: want YYYY-MM-DD: %w", err)
		}
		if b.Before(a) {
			return errors.New("--history-before is earlier than --history-after")
		}
		opts.History = &ingest.History{
			Launchpad: &launchpad.Client{HTTP: &http.Client{Timeout: 2 * time.Minute}},
			After:     a,
			Before:    b.Add(24*time.Hour - time.Second), // inclusive end of day
		}
	default:
		return fmt.Errorf("--history %q: only \"launchpad\" is supported", *history)
	}
	if len(pathsFrom) > 0 && !*all {
		seen := map[string]bool{}
		var files []attest.File
		for _, name := range pathsFrom {
			fs, err := attest.ReadFile(name)
			if err != nil {
				return err
			}
			for _, f := range fs {
				if !seen[f.Path] {
					seen[f.Path] = true
					files = append(files, f)
				}
			}
		}
		for _, f := range files {
			if c := attest.Classify(f.Path); c != attest.CatNotSystem && c != attest.CatPyc {
				opts.Targets = append(opts.Targets, f.Path)
			} else if c == attest.CatPyc {
				// Ingest the package owning the .py so .pyc can be attributed.
				if src, ok := attest.PycSource(f.Path); ok {
					opts.Targets = append(opts.Targets, src)
				}
			}
		}
		fmt.Fprintf(os.Stderr, "targeting %d system paths from %s\n", len(opts.Targets), strings.Join(pathsFrom, ", "))
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	rep, err := ingest.Run(ctx, st, opts)
	if rep != nil {
		fmt.Fprintf(os.Stderr, "\nindexes=%d listed=%d wanted-packages=%d target-paths=%d found-in-contents=%d\n",
			rep.Indexes, rep.Listed, rep.Wanted, rep.TargetPaths, rep.FoundPaths)
		fmt.Fprintf(os.Stderr, "debs: selected=%d already-indexed=%d downloaded=%d failed=%d bytes=%.1fMB files=%d in %s\n",
			rep.UniqueDebs, rep.AlreadyHad, rep.Downloaded, len(rep.Failed), float64(rep.Bytes)/1e6, rep.FilesIndexed, rep.Duration.Round(time.Second))
		for _, f := range rep.Failed {
			fmt.Fprintln(os.Stderr, "  failed:", f)
		}
	}
	return err
}

func cmdReport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	db := fs.String("db", "debhash.db", "SQLite database path")
	att := fs.String("attestation", "", "witness attestation (DSSE envelope or statement)")
	distro := fs.String("distro", "", "only match this distro")
	suite := fs.String("suite", "", "only match this suite (and its pockets)")
	arch := fs.String("arch", "", "only match this arch (plus 'all')")
	asJSON := fs.Bool("json", false, "print JSON")
	misses := fs.Int("misses", 40, "max misses to list (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *att == "" {
		return errors.New("--attestation is required")
	}
	files, err := attest.ReadFile(*att)
	if err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	filter := store.Filter{Distro: *distro, Suite: *suite, Arch: *arch}
	if filter == (store.Filter{}) {
		if filter, err = report.DetectFilter(ctx, st, files); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "detected: distro=%q suite=%q arch=%q\n", filter.Distro, filter.Suite, filter.Arch)
	}
	r, err := report.Build(ctx, st, files, filter)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	r.WriteText(os.Stdout, *misses)
	return nil
}

func cmdLookup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
	db := fs.String("db", "debhash.db", "SQLite database path")
	suite := fs.String("suite", "", "only match this suite")
	arch := fs.String("arch", "", "only match this arch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := st.Lookup(ctx, fs.Args(), store.Filter{Suite: *suite, Arch: *arch}, 0)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func cmdInspect(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: debhash inspect file.deb")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	pkg, err := deb.Read(f)
	if err != nil {
		return err
	}
	c := pkg.Control
	fmt.Printf("# %s %s %s (source %s %s)\n", c.Package, c.Version, c.Architecture, c.Source, c.SourceVersion)
	for _, e := range pkg.Entries {
		switch e.Kind {
		case deb.KindSymlink:
			fmt.Printf("%-64s  %s -> %s\n", "symlink", e.Path, e.LinkTarget)
		default:
			fmt.Printf("%s  %s\n", e.SHA256, e.Path)
		}
	}
	return nil
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	db := fs.String("db", "debhash.db", "SQLite database path")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	srv := &http.Server{Addr: *addr, Handler: server.Handler(st), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown) //nolint:errcheck
	}()
	log.Printf("debhash serving %s on http://%s", *db, *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func cmdStats(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	db := fs.String("db", "debhash.db", "SQLite database path")
	versions := fs.Bool("versions", false, "report version depth and duplication instead of coverage")
	asJSON := fs.Bool("json", false, "with --versions: print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	if *versions {
		vs, err := st.VersionStats(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(vs)
		}
		size := int64(0)
		if fi, err := os.Stat(*db); err == nil {
			size = fi.Size()
		}
		writeVersionStats(os.Stdout, vs, size)
		return nil
	}
	s, err := st.Stats(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func writeVersionStats(w io.Writer, vs *store.VersionStats, dbSize int64) {
	fmt.Fprintf(w, "Packages: %d   debs (package versions): %d   database: %.1f MB\n", vs.Packages, vs.Debs, float64(dbSize)/1e6)
	fmt.Fprintf(w, "Versions per package: min %d, median %.1f, p90 %d, max %d\n", vs.VersionsMin, vs.VersionsMedian, vs.VersionsP90, vs.VersionsMax)
	fmt.Fprintf(w, "File rows: %d   distinct (package, path, hash): %d   duplication: %.1fx\n", vs.FileRows, vs.DistinctContent, vs.Duplication)
	fmt.Fprintf(w, "Paths whose content never changes across versions: %.0f%%\n\n", 100*vs.StablePaths)
	fmt.Fprintf(w, "%-28s %9s %7s %16s\n", "deepest packages", "versions", "paths", "version-defining")
	for _, d := range vs.Top {
		fmt.Fprintf(w, "%-28s %9d %7d %16d\n", d.Name, d.Versions, d.Paths, d.Defining)
	}
}

func cmdEval(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	db := fs.String("db", "debhash.db", "SQLite database path")
	mode := fs.String("mode", "synthetic", "synthetic (query each deb with its own files), missing (same, with that deb hidden) or truth (compare with a dpkg list)")
	strategies := fs.String("strategies", "all,binaries,one", "synthetic/missing: all, binaries, one, touched")
	var touchedFrom stringList
	fs.Var(&touchedFrom, "touched", "attestation whose opened files define the 'touched' strategy; repeatable")
	sample := fs.Int("sample", 0, "evaluate this many random debs (0 = all)")
	seed := fs.Int64("seed", 1, "random seed for sampling and the 'one' strategy")
	suite := fs.String("suite", "", "only match this suite")
	arch := fs.String("arch", "", "only match this arch")
	att := fs.String("attestation", "", "truth: attestation or system-files JSON")
	dpkgPath := fs.String("dpkg", "", "truth: dpkg-query -W output (name<TAB>version)")
	asJSON := fs.Bool("json", false, "print JSON")
	maxWrong := fs.Int("wrong", 25, "list at most this many wrong answers (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	filter := store.Filter{Suite: *suite, Arch: *arch}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if *mode == "truth" {
		if *att == "" || *dpkgPath == "" {
			return errors.New("truth mode needs --attestation and --dpkg")
		}
		files, err := attest.ReadFile(*att)
		if err != nil {
			return err
		}
		df, err := os.Open(*dpkgPath)
		if err != nil {
			return err
		}
		dpkg, err := eval.ReadDpkg(df)
		df.Close()
		if err != nil {
			return err
		}
		if filter == (store.Filter{}) {
			if filter, err = report.DetectFilter(ctx, st, files); err != nil {
				return err
			}
		}
		tr, err := eval.Truth(ctx, st, files, dpkg, filter)
		if err != nil {
			return err
		}
		if *asJSON {
			return enc.Encode(tr)
		}
		eval.WriteTruth(os.Stdout, *att, tr)
		return nil
	}

	o := eval.Options{Filter: filter, Sample: *sample, Seed: *seed}
	for _, s := range splitList(*strategies) {
		o.Strategies = append(o.Strategies, eval.Strategy(s))
	}
	if len(touchedFrom) > 0 {
		o.Touched = map[string]bool{}
		for _, name := range touchedFrom {
			files, err := attest.ReadFile(name)
			if err != nil {
				return err
			}
			for _, f := range files {
				o.Touched[f.Path] = true
			}
		}
	}
	var sums []eval.Summary
	var cases []eval.Case
	switch *mode {
	case "synthetic":
		sums, cases, err = eval.Synthetic(ctx, st, o)
	case "missing":
		sums, cases, err = eval.Missing(ctx, st, o)
	default:
		return fmt.Errorf("--mode %q: want synthetic, missing or truth", *mode)
	}
	if err != nil {
		return err
	}
	if *asJSON {
		return enc.Encode(map[string]any{"mode": *mode, "summaries": sums, "cases": cases})
	}
	title := "Each deb queried with its own files (right answer known):"
	if *mode == "missing" {
		title = "Each deb queried with its own files, with that deb HIDDEN (right answer absent; any exact answer is an over-promise):"
	}
	eval.WriteSummaries(os.Stdout, title, sums)
	eval.WriteWrong(os.Stdout, cases, *maxWrong)
	return nil
}
