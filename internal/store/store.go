// Package store persists the file-hash → package index in SQLite.
//
// Schema (one row per thing we know, no duplication of package metadata):
//
//	packages      one row per distinct .deb (keyed by the deb's own sha256)
//	publications  where that .deb was published: distro, suite, component, mirror
//	files         every non-directory entry of the .deb, with its sha256
//
// The same .deb is often published in several pockets (noble and
// noble-updates) and, for Architecture: all, under several architectures; it
// is downloaded and stored once and gets one publication row per place.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	pathpkg "path"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers "sqlite"

	"github.com/jd869/debhash/internal/deb"
)

const schema = `
CREATE TABLE IF NOT EXISTS packages (
  id             INTEGER PRIMARY KEY,
  deb_sha256     TEXT NOT NULL UNIQUE,
  name           TEXT NOT NULL,
  version        TEXT NOT NULL,
  arch           TEXT NOT NULL,
  source         TEXT NOT NULL,
  source_version TEXT NOT NULL,
  filename       TEXT NOT NULL,
  size           INTEGER NOT NULL,
  ingested_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS packages_name ON packages(name, version);

CREATE TABLE IF NOT EXISTS publications (
  package_id     INTEGER NOT NULL REFERENCES packages(id),
  distro         TEXT NOT NULL,  -- ubuntu, debian
  distro_version TEXT NOT NULL,  -- 24.04, 12
  suite          TEXT NOT NULL,  -- noble-updates
  component      TEXT NOT NULL,  -- main
  mirror         TEXT NOT NULL,  -- base URL, identifies snapshots
  UNIQUE(package_id, distro, suite, component, mirror)
);
CREATE INDEX IF NOT EXISTS publications_pkg ON publications(package_id);

CREATE TABLE IF NOT EXISTS files (
  package_id  INTEGER NOT NULL REFERENCES packages(id),
  path        TEXT NOT NULL,
  sha256      TEXT,             -- NULL for symlinks
  size        INTEGER,
  kind        TEXT NOT NULL,    -- file, symlink, hardlink
  link_target TEXT,
  conffile    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS files_sha256 ON files(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS files_pkg ON files(package_id);
`

// Store is an open index database.
type Store struct{ db *sql.DB }

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite has one writer; keep it simple and safe.
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Publication says where a .deb was published.
type Publication struct {
	Distro        string // lower-case: ubuntu, debian
	DistroVersion string
	Suite         string
	Component     string
	Mirror        string
}

// PackageMeta describes a .deb as listed in a Packages index.
type PackageMeta struct {
	DebSHA256     string
	Name          string
	Version       string
	Arch          string
	Source        string
	SourceVersion string
	Filename      string
	Size          int64
}

// PackageID returns the id of an already-ingested .deb.
func (s *Store) PackageID(ctx context.Context, debSHA256 string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM packages WHERE deb_sha256 = ?`, strings.ToLower(debSHA256)).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return id, err == nil, err
}

// AddPublication records that an ingested package is published at pub.
func (s *Store) AddPublication(ctx context.Context, id int64, pub Publication) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO publications
		(package_id, distro, distro_version, suite, component, mirror) VALUES (?,?,?,?,?,?)`,
		id, pub.Distro, pub.DistroVersion, pub.Suite, pub.Component, pub.Mirror)
	return err
}

// AddPackage stores a parsed .deb and its publication in one transaction.
func (s *Store) AddPackage(ctx context.Context, meta PackageMeta, pub Publication, entries []deb.Entry) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	res, err := tx.ExecContext(ctx, `INSERT INTO packages
		(deb_sha256, name, version, arch, source, source_version, filename, size, ingested_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		strings.ToLower(meta.DebSHA256), meta.Name, meta.Version, meta.Arch, meta.Source, meta.SourceVersion,
		meta.Filename, meta.Size, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert package %s: %w", meta.Name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO files
		(package_id, path, sha256, size, kind, link_target, conffile) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, e := range entries {
		var sha, target any
		if e.SHA256 != "" {
			sha = e.SHA256
		}
		if e.LinkTarget != "" {
			target = e.LinkTarget
		}
		if _, err := stmt.ExecContext(ctx, id, e.Path, sha, e.Size, string(e.Kind), target, e.Conffile); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO publications
		(package_id, distro, distro_version, suite, component, mirror) VALUES (?,?,?,?,?,?)`,
		id, pub.Distro, pub.DistroVersion, pub.Suite, pub.Component, pub.Mirror); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// Filter narrows lookups. Empty fields match everything.
type Filter struct {
	Distro string // ubuntu
	Suite  string // noble: also matches noble-updates, noble-security, ...
	Arch   string // arm64: also matches "all"
}

// Candidate is one (file, package, publication) that has a given sha256.
type Candidate struct {
	SHA256        string `json:"sha256"`
	Path          string `json:"path"`
	Conffile      bool   `json:"conffile,omitempty"`
	PackageID     int64  `json:"package_id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Distro        string `json:"distro"`
	DistroVersion string `json:"distro_version"`
	Suite         string `json:"suite"`
	Component     string `json:"component"`
	PURL          string `json:"purl"`
}

// Result is the lookup answer for one sha256.
type Result struct {
	SHA256 string `json:"sha256"`
	// Fanout is the number of distinct package names shipping this content.
	// High fanout (CA certs, locale data, licences) means the file alone says
	// little about which package is installed.
	Fanout     int         `json:"fanout"`
	Candidates []Candidate `json:"candidates"`
	Truncated  bool        `json:"truncated,omitempty"`
}

// Lookup returns, for each hash that is in the index, its candidates. Hashes
// with no match are absent from the map. limit caps candidates per hash (0 =
// no cap); Fanout is always computed over all matches.
func (s *Store) Lookup(ctx context.Context, hashes []string, f Filter, limit int) (map[string]*Result, error) {
	out := map[string]*Result{}
	const batch = 500
	for start := 0; start < len(hashes); start += batch {
		end := min(start+batch, len(hashes))
		if err := s.lookupBatch(ctx, hashes[start:end], f, out); err != nil {
			return nil, err
		}
	}
	for _, r := range out {
		names := map[string]bool{}
		for _, c := range r.Candidates {
			names[c.Name] = true
		}
		r.Fanout = len(names)
		sort.Slice(r.Candidates, func(i, j int) bool {
			a, b := r.Candidates[i], r.Candidates[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Version != b.Version {
				return a.Version < b.Version
			}
			if a.Suite != b.Suite {
				return a.Suite < b.Suite
			}
			return a.Path < b.Path
		})
		if limit > 0 && len(r.Candidates) > limit {
			r.Candidates = r.Candidates[:limit]
			r.Truncated = true
		}
	}
	return out, nil
}

func (s *Store) lookupBatch(ctx context.Context, hashes []string, f Filter, out map[string]*Result) error {
	if len(hashes) == 0 {
		return nil
	}
	args := make([]any, 0, len(hashes)+4)
	ph := make([]string, len(hashes))
	for i, h := range hashes {
		ph[i] = "?"
		args = append(args, strings.ToLower(h))
	}
	q := `SELECT DISTINCT f.sha256, f.path, f.conffile, p.id, p.name, p.version, p.arch, p.source, p.source_version,
	             pub.distro, pub.distro_version, pub.suite, pub.component
	      FROM files f
	      JOIN packages p ON p.id = f.package_id
	      JOIN publications pub ON pub.package_id = p.id
	      WHERE f.sha256 IN (` + strings.Join(ph, ",") + `)`
	q, args = f.apply(q, args)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c Candidate
		if err := rows.Scan(&c.SHA256, &c.Path, &c.Conffile, &c.PackageID, &c.Name, &c.Version, &c.Arch,
			&c.Source, &c.SourceVersion, &c.Distro, &c.DistroVersion, &c.Suite, &c.Component); err != nil {
			return err
		}
		c.PURL = PURL(c)
		r := out[c.SHA256]
		if r == nil {
			r = &Result{SHA256: c.SHA256}
			out[c.SHA256] = r
		}
		r.Candidates = append(r.Candidates, c)
	}
	return rows.Err()
}

// PURL builds a package URL in the format syft emits, so packages found by
// hash dedupe against packages syft finds in the dpkg database:
//
//	pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4?arch=arm64&upstream=glibc&distro=ubuntu-24.04
func PURL(c Candidate) string {
	var b strings.Builder
	b.WriteString("pkg:deb/")
	b.WriteString(c.Distro)
	b.WriteString("/")
	b.WriteString(url.PathEscape(c.Name))
	b.WriteString("@")
	// Epochs ("1:2.3-1") contain ':' which purl requires percent-encoded.
	b.WriteString(strings.ReplaceAll(url.PathEscape(c.Version), ":", "%3A"))
	q := []string{"arch=" + url.QueryEscape(c.Arch)}
	if c.Source != "" && c.Source != c.Name {
		up := c.Source
		if c.SourceVersion != "" && c.SourceVersion != c.Version {
			up += "@" + c.SourceVersion
		}
		q = append(q, "upstream="+url.QueryEscape(up))
	}
	if c.DistroVersion != "" {
		q = append(q, "distro="+url.QueryEscape(c.Distro+"-"+c.DistroVersion))
	}
	b.WriteString("?")
	b.WriteString(strings.Join(q, "&"))
	return b.String()
}

// LookupPaths returns the packages that ship each of the given absolute
// paths. It backs path-based fallbacks such as attributing a generated
// __pycache__/*.pyc to the package that owns its .py source.
func (s *Store) LookupPaths(ctx context.Context, paths []string, f Filter) (map[string][]Candidate, error) {
	out := map[string][]Candidate{}
	const batch = 500
	for start := 0; start < len(paths); start += batch {
		chunk := paths[start:min(start+batch, len(paths))]
		args := make([]any, 0, len(chunk)+4)
		ph := make([]string, len(chunk))
		for i, p := range chunk {
			ph[i] = "?"
			args = append(args, p)
		}
		q := `SELECT DISTINCT COALESCE(f.sha256,''), f.path, f.conffile, p.id, p.name, p.version, p.arch, p.source, p.source_version,
		             pub.distro, pub.distro_version, pub.suite, pub.component
		      FROM files f JOIN packages p ON p.id = f.package_id JOIN publications pub ON pub.package_id = p.id
		      WHERE f.path IN (` + strings.Join(ph, ",") + `)`
		q, args = f.apply(q, args)
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c Candidate
			if err := rows.Scan(&c.SHA256, &c.Path, &c.Conffile, &c.PackageID, &c.Name, &c.Version, &c.Arch,
				&c.Source, &c.SourceVersion, &c.Distro, &c.DistroVersion, &c.Suite, &c.Component); err != nil {
				rows.Close()
				return nil, err
			}
			c.PURL = PURL(c)
			out[c.Path] = append(out[c.Path], c)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// SymlinkTargets returns, for each of paths that some indexed package ships
// as a symlink, the absolute path the link points to.
func (s *Store) SymlinkTargets(ctx context.Context, paths []string) (map[string]string, error) {
	out := map[string]string{}
	err := s.inPaths(ctx, `SELECT DISTINCT path, link_target FROM files WHERE kind = 'symlink' AND path IN (%s)`, paths,
		func(rows *sql.Rows) error {
			var p, target string
			if err := rows.Scan(&p, &target); err != nil {
				return err
			}
			if !strings.HasPrefix(target, "/") {
				target = pathpkg.Join(pathpkg.Dir(p), target)
			}
			out[p] = pathpkg.Clean(target)
			return nil
		})
	return out, err
}

// FileOwners returns, for each of paths that some indexed package ships as a
// regular file (or hardlink), the names of those packages.
func (s *Store) FileOwners(ctx context.Context, paths []string) (map[string][]string, error) {
	out := map[string][]string{}
	err := s.inPaths(ctx, `SELECT DISTINCT f.path, p.name FROM files f JOIN packages p ON p.id = f.package_id
		WHERE f.kind != 'symlink' AND f.path IN (%s)`, paths,
		func(rows *sql.Rows) error {
			var p, name string
			if err := rows.Scan(&p, &name); err != nil {
				return err
			}
			out[p] = append(out[p], name)
			return nil
		})
	return out, err
}

// inPaths runs query (with one %s for the IN list) over paths in batches.
func (s *Store) inPaths(ctx context.Context, query string, paths []string, scan func(*sql.Rows) error) error {
	const batch = 500
	for start := 0; start < len(paths); start += batch {
		chunk := paths[start:min(start+batch, len(paths))]
		args := make([]any, len(chunk))
		ph := make([]string, len(chunk))
		for i, p := range chunk {
			args[i], ph[i] = p, "?"
		}
		rows, err := s.db.QueryContext(ctx, fmt.Sprintf(query, strings.Join(ph, ",")), args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := scan(rows); err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// apply appends the filter's WHERE clauses (the query must already have one).
func (f Filter) apply(q string, args []any) (string, []any) {
	if f.Distro != "" {
		q += ` AND pub.distro = ?`
		args = append(args, strings.ToLower(f.Distro))
	}
	if f.Suite != "" {
		q += ` AND (pub.suite = ? OR pub.suite LIKE ?)`
		args = append(args, f.Suite, f.Suite+"-%")
	}
	if f.Arch != "" {
		q += ` AND (p.arch = ? OR p.arch = 'all')`
		args = append(args, f.Arch)
	}
	return q, args
}

// File is one row of a package manifest.
type File struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Kind       string `json:"kind"`
	LinkTarget string `json:"link_target,omitempty"`
	Conffile   bool   `json:"conffile,omitempty"`
}

// PackageFiles returns the full file manifest of an ingested package.
func (s *Store) PackageFiles(ctx context.Context, id int64) ([]File, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT path, COALESCE(sha256,''), COALESCE(size,0), kind, COALESCE(link_target,''), conffile
		FROM files WHERE package_id = ? ORDER BY path`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.Path, &f.SHA256, &f.Size, &f.Kind, &f.LinkTarget, &f.Conffile); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Coverage is one indexed (distro, suite, component, arch) slice.
type Coverage struct {
	Distro        string `json:"distro"`
	DistroVersion string `json:"distro_version"`
	Suite         string `json:"suite"`
	Component     string `json:"component"`
	Arch          string `json:"arch"`
	Mirror        string `json:"mirror"`
	Packages      int    `json:"packages"`
	LastIngested  string `json:"last_ingested"`
}

// Stats summarises what the index covers.
type Stats struct {
	Packages int        `json:"packages"`
	Files    int        `json:"files"`
	Hashes   int        `json:"distinct_hashes"`
	Coverage []Coverage `json:"coverage"`
}

// Stats returns index totals and per-suite coverage, so clients can tell
// what is (and is not) indexed and how fresh it is.
func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM packages`).Scan(&st.Packages); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT sha256) FROM files`).Scan(&st.Files, &st.Hashes); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT pub.distro, pub.distro_version, pub.suite, pub.component, p.arch, pub.mirror,
		COUNT(DISTINCT p.id), MAX(p.ingested_at)
		FROM publications pub JOIN packages p ON p.id = pub.package_id
		GROUP BY 1,2,3,4,5,6 ORDER BY 1,3,4,5,6`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Coverage
		if err := rows.Scan(&c.Distro, &c.DistroVersion, &c.Suite, &c.Component, &c.Arch, &c.Mirror, &c.Packages, &c.LastIngested); err != nil {
			return nil, err
		}
		st.Coverage = append(st.Coverage, c)
	}
	return st, rows.Err()
}
