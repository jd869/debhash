package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jd869/debhash/internal/deb"
	"github.com/jd869/debhash/internal/debtest"
	"github.com/jd869/debhash/internal/store"
)

func setup(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash := debtest.SHA256("libc bytes")
	_, err = st.AddPackage(context.Background(),
		store.PackageMeta{DebSHA256: debtest.SHA256("deb"), Name: "libc6", Version: "2.39-0ubuntu8.4", Arch: "arm64", Source: "glibc", SourceVersion: "2.39-0ubuntu8.4"},
		store.Publication{Distro: "ubuntu", DistroVersion: "24.04", Suite: "noble-updates", Component: "main", Mirror: "m"},
		[]deb.Entry{{Path: "/usr/lib/aarch64-linux-gnu/libc.so.6", Kind: deb.KindFile, SHA256: hash, Size: 10}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(st))
	t.Cleanup(srv.Close)
	return srv, hash
}

func get(t *testing.T, url string, into any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if into != nil {
		json.NewDecoder(resp.Body).Decode(into)
	}
	return resp.StatusCode
}

func TestEndpoints(t *testing.T) {
	srv, hash := setup(t)
	missing := strings.Repeat("0", 64)

	var one store.Result
	if code := get(t, srv.URL+"/v1/sha256/"+strings.ToUpper(hash)+"?suite=noble&arch=arm64", &one); code != 200 {
		t.Fatalf("lookup status %d", code)
	}
	if one.Fanout != 1 || one.Candidates[0].PURL != "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4?arch=arm64&upstream=glibc&distro=ubuntu-24.04" {
		t.Fatalf("lookup = %+v", one)
	}
	if code := get(t, srv.URL+"/v1/sha256/"+hash+"?arch=amd64", nil); code != 404 {
		t.Fatalf("arch filter: status %d", code)
	}
	if code := get(t, srv.URL+"/v1/sha256/nothex", nil); code != 400 {
		t.Fatalf("bad hash: status %d", code)
	}

	body := `{"hashes":["` + hash + `","` + missing + `","` + hash + `"],"hint":{"distro":"ubuntu","suite":"noble","arch":"arm64"}}`
	resp, err := http.Post(srv.URL+"/v1/bulk/sha256", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var bulk BulkResponse
	json.NewDecoder(resp.Body).Decode(&bulk)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(bulk.Results) != 1 || len(bulk.Missing) != 1 || bulk.Missing[0] != missing {
		t.Fatalf("bulk = %d %+v", resp.StatusCode, bulk)
	}

	for _, bad := range []string{`{"hashes":[]}`, `{"hashes":["zz"]}`, `{"nope":1}`, `not json`} {
		resp, err := http.Post(srv.URL+"/v1/bulk/sha256", "application/json", strings.NewReader(bad))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("bulk %s: status %d, want 400", bad, resp.StatusCode)
		}
	}

	var files struct {
		Files []store.File `json:"files"`
	}
	if code := get(t, srv.URL+"/v1/packages/"+strconv.FormatInt(one.Candidates[0].PackageID, 10)+"/files", &files); code != 200 || len(files.Files) != 1 {
		t.Fatalf("files = %d %+v", code, files)
	}
	if code := get(t, srv.URL+"/v1/packages/999/files", nil); code != 404 {
		t.Fatalf("unknown package: status %d", code)
	}
	var stats store.Stats
	if code := get(t, srv.URL+"/v1/stats", &stats); code != 200 || stats.Packages != 1 || len(stats.Coverage) != 1 {
		t.Fatalf("stats = %d %+v", code, stats)
	}
}
