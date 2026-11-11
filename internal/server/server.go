// Package server exposes the index over HTTP/JSON.
//
//	GET  /v1/sha256/{hash}?distro=&suite=&arch=&limit=   one lookup
//	POST /v1/bulk/sha256                                 many lookups
//	     {"hashes": [...], "hint": {"distro","suite","arch"}, "limit": n}
//	POST /v1/attribute                                   files -> packages
//	     {"files": [{"path","sha256"}], "hint": {...}}   (hint optional: detected)
//	GET  /v1/packages/{id}/files                         package manifest
//	GET  /v1/stats                                       coverage + freshness
//	GET  /healthz
package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/jd869/debhash/internal/attest"
	"github.com/jd869/debhash/internal/report"
	"github.com/jd869/debhash/internal/store"
)

// MaxBulk caps hashes per bulk request.
const MaxBulk = 1000

// MaxAttribute caps files per attribute request.
const MaxAttribute = 20000

// DefaultLimit caps candidates per hash unless the client asks otherwise.
const DefaultLimit = 100

// Handler returns the HTTP handler for st.
func Handler(st *store.Store) http.Handler {
	s := &srv{st: st}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sha256/{hash}", s.one)
	mux.HandleFunc("POST /v1/bulk/sha256", s.bulk)
	mux.HandleFunc("POST /v1/attribute", s.attribute)
	mux.HandleFunc("GET /v1/packages/{id}/files", s.files)
	mux.HandleFunc("GET /v1/stats", s.stats)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

type srv struct{ st *store.Store }

// Hint narrows a lookup to the system the attestation came from.
type Hint struct {
	Distro string `json:"distro,omitempty"`
	Suite  string `json:"suite,omitempty"`
	Arch   string `json:"arch,omitempty"`
}

// BulkRequest is the body of POST /v1/bulk/sha256.
type BulkRequest struct {
	Hashes []string `json:"hashes"`
	Hint   Hint     `json:"hint"`
	Limit  int      `json:"limit,omitempty"`
}

// BulkResponse lists found hashes; hashes not in the index are listed in Missing.
type BulkResponse struct {
	Results []*store.Result `json:"results"`
	Missing []string        `json:"missing"`
}

func (s *srv) one(w http.ResponseWriter, r *http.Request) {
	h := strings.ToLower(r.PathValue("hash"))
	if !validSHA256(h) {
		httpError(w, http.StatusBadRequest, "hash must be 64 hex characters")
		return
	}
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.st.Lookup(r.Context(), []string{h}, store.Filter{Distro: q.Get("distro"), Suite: q.Get("suite"), Arch: q.Get("arch")}, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	if res[h] == nil {
		httpError(w, http.StatusNotFound, "hash not in index")
		return
	}
	writeJSON(w, res[h])
}

func (s *srv) bulk(w http.ResponseWriter, r *http.Request) {
	var req BulkRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(req.Hashes) == 0 || len(req.Hashes) > MaxBulk {
		httpError(w, http.StatusBadRequest, "hashes must contain 1.."+strconv.Itoa(MaxBulk)+" entries")
		return
	}
	seen := map[string]bool{}
	hashes := make([]string, 0, len(req.Hashes))
	for _, h := range req.Hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if !validSHA256(h) {
			httpError(w, http.StatusBadRequest, "invalid sha256: "+h)
			return
		}
		if !seen[h] {
			seen[h] = true
			hashes = append(hashes, h)
		}
	}
	limit := req.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	res, err := s.st.Lookup(r.Context(), hashes, store.Filter{Distro: req.Hint.Distro, Suite: req.Hint.Suite, Arch: req.Hint.Arch}, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := BulkResponse{Results: []*store.Result{}, Missing: []string{}}
	for _, h := range hashes {
		if v := res[h]; v != nil {
			out.Results = append(out.Results, v)
		} else {
			out.Missing = append(out.Missing, h)
		}
	}
	writeJSON(w, out)
}

// AttributeRequest is the body of POST /v1/attribute.
type AttributeRequest struct {
	Files []attest.File `json:"files"`
	// Hint narrows matching; empty fields are detected from the files.
	Hint Hint `json:"hint"`
}

// AttributeResponse is the attribution plus the filter actually used.
type AttributeResponse struct {
	Hint Hint `json:"hint"`
	*report.Report
}

// attribute runs the full attribution (anchors, version intersection,
// source-version propagation, .pyc via source) over a set of attested files
// and returns the identified packages with the files assigned to each.
func (s *srv) attribute(w http.ResponseWriter, r *http.Request) {
	var req AttributeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if len(req.Files) == 0 || len(req.Files) > MaxAttribute {
		httpError(w, http.StatusBadRequest, "files must contain 1.."+strconv.Itoa(MaxAttribute)+" entries")
		return
	}
	seen := map[string]bool{}
	files := make([]attest.File, 0, len(req.Files))
	for _, f := range req.Files {
		h := strings.ToLower(strings.TrimSpace(f.SHA256))
		if !strings.HasPrefix(f.Path, "/") || !validSHA256(h) {
			httpError(w, http.StatusBadRequest, "each file needs an absolute path and a sha256: "+f.Path)
			return
		}
		p := path.Clean(f.Path)
		if !seen[p] {
			seen[p] = true
			files = append(files, attest.File{Path: p, SHA256: h})
		}
	}
	detected, err := report.DetectFilter(r.Context(), s.st, files)
	if err != nil {
		s.internal(w, err)
		return
	}
	filter := store.Filter{Distro: req.Hint.Distro, Suite: req.Hint.Suite, Arch: req.Hint.Arch}
	if filter.Distro == "" {
		filter.Distro = detected.Distro
	}
	if filter.Suite == "" {
		filter.Suite = detected.Suite
	}
	if filter.Arch == "" {
		filter.Arch = detected.Arch
	}
	rep, err := report.Build(r.Context(), s.st, files, filter)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, AttributeResponse{Hint: Hint{Distro: filter.Distro, Suite: filter.Suite, Arch: filter.Arch}, Report: rep})
}

func (s *srv) files(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpError(w, http.StatusBadRequest, "id must be a positive integer")
		return
	}
	files, err := s.st.PackageFiles(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	if len(files) == 0 {
		httpError(w, http.StatusNotFound, "package not found")
		return
	}
	writeJSON(w, map[string]any{"package_id": id, "files": files})
}

func (s *srv) stats(w http.ResponseWriter, r *http.Request) {
	st, err := s.st.Stats(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, st)
}

func (s *srv) internal(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	httpError(w, http.StatusInternalServerError, "internal error")
}

func validSHA256(h string) bool {
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

func parseLimit(s string) (int, error) {
	if s == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, errors.New("limit must be a non-negative integer")
	}
	return n, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
