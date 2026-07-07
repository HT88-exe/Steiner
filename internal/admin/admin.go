// Package admin serves the loopback-only admin API: audit queries, approval
// decisions, and the read-only trace viewer.
package admin

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HT88-exe/steiner/internal/audit"
	"github.com/HT88-exe/steiner/internal/policy"
)

//go:embed trace.html
var traceHTML []byte

// Server exposes the admin HTTP API.
type Server struct {
	Audit  *audit.Log
	Broker *policy.Broker
	// Key optionally protects the API (Authorization: Bearer <key>).
	Key string
}

// Handler builds the admin mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(traceHTML)
	})
	mux.HandleFunc("GET /api/events", s.auth(s.events))
	mux.HandleFunc("GET /api/approvals", s.auth(s.approvals))
	mux.HandleFunc("POST /api/approvals/{id}", s.auth(s.decide))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Key != "" {
			token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if strings.TrimSpace(token) != s.Key {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid admin key"})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := audit.Query{
		Principal: r.URL.Query().Get("principal"),
		Decision:  r.URL.Query().Get("decision"),
		Tool:      r.URL.Query().Get("tool"),
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since = t
		}
	}
	events, err := s.Audit.Events(q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []audit.Event{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Broker.Pending())
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Approve bool `json:"approve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"approve\": true|false}"})
		return
	}
	if err := s.Broker.Decide(r.PathValue("id"), body.Approve); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
