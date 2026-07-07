package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brueing/steiner/internal/audit"
	"github.com/brueing/steiner/internal/policy"
)

func newTestServer(t *testing.T, key string) (*Server, *httptest.Server) {
	t.Helper()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	s := &Server{Audit: log, Broker: policy.NewBroker(""), Key: key}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestEventsEndpoint(t *testing.T) {
	s, ts := newTestServer(t, "")
	if err := s.Audit.Record(&audit.Event{Principal: "a", Tool: "t", Decision: "allowed"}); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(ts.URL + "/api/events?principal=a")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var events []audit.Event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Principal != "a" {
		t.Fatalf("events = %+v", events)
	}

	resp2, err := http.Get(ts.URL + "/api/events?principal=nobody")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var empty []audit.Event
	if err := json.NewDecoder(resp2.Body).Decode(&empty); err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected empty list, got %+v", empty)
	}
}

func TestAdminKey(t *testing.T) {
	_, ts := newTestServer(t, "secret-admin-key")

	resp, err := http.Get(ts.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing key: got %d", resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-admin-key")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("valid key: got %d", resp2.StatusCode)
	}
}

func TestApprovalFlow(t *testing.T) {
	s, ts := newTestServer(t, "")

	got := make(chan bool, 1)
	go func() {
		ok, _ := s.Broker.Request(context.Background(), "p", "shell_run", `{"cmd":"ls"}`, "why", 5*time.Second)
		got <- ok
	}()

	// Wait for it to appear in the pending list.
	var id string
	deadline := time.Now().Add(2 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		resp, err := http.Get(ts.URL + "/api/approvals")
		if err != nil {
			t.Fatal(err)
		}
		var pending []map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if len(pending) > 0 {
			id = pending[0]["id"].(string)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if id == "" {
		t.Fatal("approval never appeared in the queue")
	}

	resp, err := http.Post(ts.URL+"/api/approvals/"+id, "application/json", strings.NewReader(`{"approve":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide: got %d", resp.StatusCode)
	}
	if ok := <-got; !ok {
		t.Fatal("request should have been approved")
	}

	// Unknown ID -> 404.
	resp2, err := http.Post(ts.URL+"/api/approvals/nope", "application/json", strings.NewReader(`{"approve":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: got %d", resp2.StatusCode)
	}
}
