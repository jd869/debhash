// Package launchpad lists historical Ubuntu binary package versions.
//
// Ubuntu mirrors keep only the newest version of each package, but Launchpad,
// where Ubuntu builds everything, keeps every version ever published, with
// its publish and supersede dates and a download URL plus sha256 per deb. For
// a build at time T, the installed version was one that was live (published
// and not yet superseded) shortly before T.
//
// API reference: https://api.launchpad.net/devel.html#archive
// (getPublishedBinaries, binary_package_publishing_history.binaryFileUrls).
package launchpad

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jd869/debhash/internal/archive"
)

// DefaultAPI is the Launchpad web service root.
const DefaultAPI = "https://api.launchpad.net/1.0"

// Client talks to the Launchpad API.
type Client struct {
	API  string // default DefaultAPI
	HTTP *http.Client
}

// Binary is one published deb.
type Binary struct {
	Name, Version, Arch   string
	Source, SourceVersion string
	Pocket                string // Release, Updates, Security, Proposed, Backports
	Component             string
	Published, Superseded time.Time // zero when unknown / still current
	URL, SHA256           string
	Size                  int64
}

// LiveIn reports whether b was published by `before` and not superseded
// before `after`, i.e. it could have been installed in that window.
func (b Binary) LiveIn(after, before time.Time) bool {
	if b.Published.IsZero() || b.Published.After(before) {
		return false
	}
	return b.Superseded.IsZero() || !b.Superseded.Before(after)
}

type collection struct {
	Entries []struct {
		Name          string `json:"binary_package_name"`
		Version       string `json:"binary_package_version"`
		ArchSpecific  bool   `json:"architecture_specific"`
		Pocket        string `json:"pocket"`
		Status        string `json:"status"`
		Component     string `json:"component_name"`
		Source        string `json:"source_package_name"`
		SourceVersion string `json:"source_package_version"`
		Published     string `json:"date_published"`
		Superseded    string `json:"date_superseded"`
		SelfLink      string `json:"self_link"`
	} `json:"entries"`
	Next string `json:"next_collection_link"`
}

type fileURL struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func (c *Client) api() string {
	if c.API != "" {
		return strings.TrimRight(c.API, "/")
	}
	return DefaultAPI
}

func (c *Client) getJSON(ctx context.Context, u string, into any) error {
	resp, err := archive.GetURL(ctx, c.HTTP, u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, into); err != nil {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

// Published lists every publication of binary package name in
// distro/series for arch (Architecture: all packages included), excluding
// the Proposed pocket. Download URL and sha256 are not filled in; call
// Files for the versions you want.
func (c *Client) Published(ctx context.Context, distro, series, arch, name string) ([]Binary, []string, error) {
	q := url.Values{}
	q.Set("ws.op", "getPublishedBinaries")
	q.Set("binary_name", name)
	q.Set("exact_match", "true")
	q.Set("distro_arch_series", c.api()+"/"+distro+"/"+series+"/"+arch)
	q.Set("ws.size", "300")
	next := c.api() + "/" + distro + "/+archive/primary?" + q.Encode()

	var out []Binary
	var links []string
	for next != "" {
		var col collection
		if err := c.getJSON(ctx, next, &col); err != nil {
			return nil, nil, err
		}
		for _, e := range col.Entries {
			if e.Name != name || e.Pocket == "Proposed" || e.Status == "Deleted" {
				continue
			}
			b := Binary{
				Name: e.Name, Version: e.Version, Source: e.Source, SourceVersion: e.SourceVersion,
				Pocket: e.Pocket, Component: e.Component, Arch: arch,
				Published: parseTime(e.Published), Superseded: parseTime(e.Superseded),
			}
			if !e.ArchSpecific {
				b.Arch = "all"
			}
			out = append(out, b)
			links = append(links, e.SelfLink)
		}
		next = col.Next
	}
	return out, links, nil
}

// Files returns the .deb download URL, sha256 and size of one publication.
func (c *Client) Files(ctx context.Context, selfLink string) (string, string, int64, error) {
	var files []fileURL
	if err := c.getJSON(ctx, selfLink+"?ws.op=binaryFileUrls&include_meta=true", &files); err != nil {
		return "", "", 0, err
	}
	for _, f := range files {
		if strings.HasSuffix(f.URL, ".deb") {
			return f.URL, f.SHA256, f.Size, nil
		}
	}
	return "", "", 0, fmt.Errorf("no .deb in %s", selfLink)
}

// Window returns the publications of name that were live in [after, before],
// with download URLs filled in. A version published in several pockets
// (Updates and Security) yields one Binary per pocket sharing the same URL.
func (c *Client) Window(ctx context.Context, distro, series, arch, name string, after, before time.Time) ([]Binary, error) {
	pubs, links, err := c.Published(ctx, distro, series, arch, name)
	if err != nil {
		return nil, err
	}
	type file struct {
		url, sha string
		size     int64
	}
	byVersion := map[string]file{}
	var out []Binary
	for i, b := range pubs {
		if !b.LiveIn(after, before) {
			continue
		}
		f, ok := byVersion[b.Version]
		if !ok {
			u, sha, size, err := c.Files(ctx, links[i])
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", name, b.Version, err)
			}
			f = file{u, sha, size}
			byVersion[b.Version] = f
		}
		b.URL, b.SHA256, b.Size = f.url, f.sha, f.size
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Pocket < out[j].Pocket
	})
	return out, nil
}

// Suite maps a Launchpad pocket to the APT suite name: Release -> noble,
// Updates -> noble-updates.
func Suite(series, pocket string) string {
	if pocket == "" || pocket == "Release" {
		return series
	}
	return series + "-" + strings.ToLower(pocket)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-07:00", "2006-01-02T15:04:05-07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
