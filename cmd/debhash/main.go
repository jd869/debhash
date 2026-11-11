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
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/ingest"
	"github.com/jd869/debhash/internal/launchpad"
	"github.com/jd869/debhash/internal/report"
	"github.com/jd869/debhash/internal/server"
	"github.com/jd869/debhash/internal/store"
)

const usage = `debhash: map file sha256 digests to Debian/Ubuntu packages

Commands:
  ingest   download .debs from a mirror and index every file's sha256
  report   measure how much of a witness attestation the index attributes
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
		"inspect": cmdInspect, "serve": cmdServe, "stats": cmdStats,
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
	pathsFrom := fs.String("paths-from", "", "witness attestation: only ingest packages shipping its files")
	all := fs.Bool("all", false, "ingest every package in the selected pockets/components")
	workers := fs.Int("workers", 4, "parallel downloads")
	history := fs.String("history", "", `also ingest historical versions; "launchpad" (Ubuntu only)`)
	after := fs.String("history-after", "", "history window start, YYYY-MM-DD")
	before := fs.String("history-before", "", "history window end, YYYY-MM-DD (e.g. the build date)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := ingest.Options{
		Mirror: *mirror, Distro: *distro, Suite: *suite, Pockets: splitList(*pockets),
		Components: splitList(*components), Arch: *arch, All: *all, Workers: *workers,
		Client: &http.Client{Timeout: 10 * time.Minute}, Log: os.Stderr,
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
	if *pathsFrom != "" && !*all {
		files, err := attest.ReadFile(*pathsFrom)
		if err != nil {
			return err
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
		fmt.Fprintf(os.Stderr, "targeting %d system paths from %s\n", len(opts.Targets), *pathsFrom)
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
	r, err := report.Build(ctx, st, files, store.Filter{Distro: *distro, Suite: *suite, Arch: *arch})
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openDB(*db)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := st.Stats(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
