package store

import (
	"context"
	pathpkg "path"
	"sort"
	"strings"
)

// PackageDepth describes how many versions of one package are indexed, and
// how many of its files actually change between them.
type PackageDepth struct {
	Name     string `json:"name"`
	Versions int    `json:"versions"`
	// Paths is the number of distinct file paths across all versions.
	Paths int `json:"paths"`
	// Defining is how many of those paths have more than one distinct hash
	// across the indexed versions: the files that can tell versions apart.
	Defining int `json:"version_defining_paths"`
}

// VersionStats answers "how deep is the index": versions per package, and
// how much of the stored data is repeated across versions.
type VersionStats struct {
	Packages int `json:"packages"`
	Debs     int `json:"debs"`

	VersionsMin    int     `json:"versions_min"`
	VersionsMedian float64 `json:"versions_median"`
	VersionsP90    int     `json:"versions_p90"`
	VersionsMax    int     `json:"versions_max"`

	// FileRows is one row per (deb, file): what the files table stores today.
	FileRows int `json:"file_rows"`
	// DistinctContent is the number of distinct (package, path, sha256):
	// what storing each file content once per package would need.
	DistinctContent int `json:"distinct_package_path_hash"`
	// Duplication is FileRows / DistinctContent.
	Duplication float64 `json:"duplication"`
	// StablePaths is the share of (package, path) pairs whose content is the
	// same in every indexed version of the package.
	StablePaths float64 `json:"stable_path_share"`

	Top []PackageDepth `json:"deepest_packages"`
	All []PackageDepth `json:"packages_detail"`
}

// VersionStats computes depth and duplication figures for the whole index.
func (s *Store) VersionStats(ctx context.Context) (*VersionStats, error) {
	vs := &VersionStats{}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM packages`).Scan(&vs.Debs); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM files WHERE sha256 IS NOT NULL`).Scan(&vs.FileRows); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
		SELECT DISTINCT p.name, f.path, f.sha256 FROM files f JOIN packages p ON p.id = f.package_id
		WHERE f.sha256 IS NOT NULL)`).Scan(&vs.DistinctContent); err != nil {
		return nil, err
	}
	if vs.DistinctContent > 0 {
		vs.Duplication = float64(vs.FileRows) / float64(vs.DistinctContent)
	}

	// Per package: versions, paths, and paths with more than one hash.
	rows, err := s.db.QueryContext(ctx, `
		WITH v AS (SELECT name, COUNT(DISTINCT version) AS versions FROM packages GROUP BY name),
		     ph AS (SELECT p.name, f.path, COUNT(DISTINCT f.sha256) AS hashes
		            FROM files f JOIN packages p ON p.id = f.package_id
		            WHERE f.sha256 IS NOT NULL GROUP BY p.name, f.path)
		SELECT v.name, v.versions,
		       COALESCE((SELECT COUNT(*) FROM ph WHERE ph.name = v.name), 0),
		       COALESCE((SELECT COUNT(*) FROM ph WHERE ph.name = v.name AND ph.hashes > 1), 0)
		FROM v ORDER BY v.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths, stable int
	for rows.Next() {
		var d PackageDepth
		if err := rows.Scan(&d.Name, &d.Versions, &d.Paths, &d.Defining); err != nil {
			return nil, err
		}
		vs.All = append(vs.All, d)
		paths += d.Paths
		stable += d.Paths - d.Defining
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	vs.Packages = len(vs.All)
	if paths > 0 {
		vs.StablePaths = float64(stable) / float64(paths)
	}
	if len(vs.All) == 0 {
		return vs, nil
	}

	counts := make([]int, len(vs.All))
	for i, d := range vs.All {
		counts[i] = d.Versions
	}
	sort.Ints(counts)
	n := len(counts)
	vs.VersionsMin, vs.VersionsMax = counts[0], counts[n-1]
	if n%2 == 1 {
		vs.VersionsMedian = float64(counts[n/2])
	} else {
		vs.VersionsMedian = float64(counts[n/2-1]+counts[n/2]) / 2
	}
	vs.VersionsP90 = counts[min(n-1, (n*9)/10)]

	top := append([]PackageDepth(nil), vs.All...)
	sort.Slice(top, func(i, j int) bool {
		if top[i].Versions != top[j].Versions {
			return top[i].Versions > top[j].Versions
		}
		return top[i].Name < top[j].Name
	})
	vs.Top = top[:min(10, len(top))]
	return vs, nil
}

// Deb is one ingested package version.
type Deb struct {
	ID      int64
	Name    string
	Version string
	Arch    string
}

// Debs lists every ingested deb, ordered by name and id.
func (s *Store) Debs(ctx context.Context) ([]Deb, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, version, arch FROM packages ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Deb
	for rows.Next() {
		var d Deb
		if err := rows.Scan(&d.ID, &d.Name, &d.Version, &d.Arch); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Versions returns every indexed version of every package, by name.
func (s *Store) Versions(ctx context.Context) (map[string]map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT name, version FROM packages`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for rows.Next() {
		var n, v string
		if err := rows.Scan(&n, &v); err != nil {
			return nil, err
		}
		if out[n] == nil {
			out[n] = map[string]bool{}
		}
		out[n][v] = true
	}
	return out, rows.Err()
}

// Manifest is the file list of one package version, for checking attested
// files against it.
type Manifest struct {
	Files     map[string]string // regular file path -> sha256
	Links     map[string]string // symlink path -> absolute target
	Conffiles map[string]bool
}

// DebManifest returns the file list of package name at version (respecting
// the filter's suite/arch/exclusion), or nil if no such deb is indexed.
func (s *Store) DebManifest(ctx context.Context, name, version string, f Filter) (*Manifest, error) {
	sub := `SELECT p.id FROM packages p JOIN publications pub ON pub.package_id = p.id WHERE p.name = ? AND p.version = ?`
	subArgs := []any{name, version}
	sub, subArgs = f.apply(sub, subArgs)
	q := `SELECT path, COALESCE(sha256, ''), kind, COALESCE(link_target, ''), conffile FROM files
	      WHERE package_id = (` + sub + ` ORDER BY p.id LIMIT 1)`
	rows, err := s.db.QueryContext(ctx, q, subArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := &Manifest{Files: map[string]string{}, Links: map[string]string{}, Conffiles: map[string]bool{}}
	n := 0
	for rows.Next() {
		var p, sha, kind, target string
		var conf bool
		if err := rows.Scan(&p, &sha, &kind, &target, &conf); err != nil {
			return nil, err
		}
		n++
		switch {
		case kind == "symlink" && target != "":
			if !strings.HasPrefix(target, "/") {
				target = pathpkg.Join(pathpkg.Dir(p), target)
			}
			m.Links[p] = pathpkg.Clean(target)
		case sha != "":
			m.Files[p] = sha
		}
		if conf {
			m.Conffiles[p] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return m, nil
}
