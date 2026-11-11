// Package lptest is a fake Launchpad web service for tests.
package lptest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Pub is one binary publication.
type Pub struct {
	Name, Version, Pocket string
	Published, Superseded string // RFC 3339; Superseded may be empty
	SHA256                string
	Size                  int64
	ArchIndep             bool
	Body                  []byte // served at the deb URL, if set
}

// Server fakes getPublishedBinaries, binaryFileUrls and librarian downloads.
type Server struct {
	srv       *httptest.Server
	mu        sync.Mutex
	pubs      []Pub
	fileCalls int
}

// New starts a fake server, closed when the test ends.
func New(t testing.TB) *Server {
	s := &Server{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the API root to pass as launchpad.Client.API.
func (s *Server) URL() string { return s.srv.URL }

// Add publishes p.
func (s *Server) Add(p Pub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pubs = append(s.pubs, p)
}

// FileCalls counts binaryFileUrls requests.
func (s *Server) FileCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fileCalls
}

func debName(p Pub) string {
	arch := "arm64"
	if p.ArchIndep {
		arch = "all"
	}
	return fmt.Sprintf("%s_%s_%s.deb", p.Name, p.Version, arch)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := r.URL.Query()
	switch {
	case strings.HasPrefix(r.URL.Path, "/+files/"):
		name := strings.TrimPrefix(r.URL.Path, "/+files/")
		for _, p := range s.pubs {
			if debName(p) == name && p.Body != nil {
				w.Write(p.Body)
				return
			}
		}
		http.NotFound(w, r)
	case q.Get("ws.op") == "getPublishedBinaries":
		var entries []map[string]any
		for i, p := range s.pubs {
			if p.Name != q.Get("binary_name") {
				continue
			}
			e := map[string]any{
				"binary_package_name": p.Name, "binary_package_version": p.Version,
				"architecture_specific": !p.ArchIndep, "pocket": p.Pocket, "status": "Published",
				"component_name": "main", "source_package_name": p.Name + "-src", "source_package_version": p.Version,
				"date_published": p.Published, "self_link": fmt.Sprintf("%s/ubuntu/+archive/primary/+binarypub/%d", s.srv.URL, i),
			}
			if p.Superseded != "" {
				e["date_superseded"] = p.Superseded
				e["status"] = "Superseded"
			} else {
				e["date_superseded"] = nil
			}
			entries = append(entries, e)
		}
		json.NewEncoder(w).Encode(map[string]any{"entries": entries, "total_size": len(entries)})
	case q.Get("ws.op") == "binaryFileUrls":
		s.fileCalls++
		var i int
		fmt.Sscanf(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], "%d", &i)
		if i < 0 || i >= len(s.pubs) {
			http.NotFound(w, r)
			return
		}
		p := s.pubs[i]
		json.NewEncoder(w).Encode([]map[string]any{{
			"url": s.srv.URL + "/+files/" + debName(p), "sha256": p.SHA256, "size": p.Size,
		}})
	default:
		http.NotFound(w, r)
	}
}
