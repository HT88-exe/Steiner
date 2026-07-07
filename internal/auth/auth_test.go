package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndLookup(t *testing.T) {
	keys := filepath.Join(t.TempDir(), "keys.yaml")

	tokenA, err := Generate(keys, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := Generate(keys, "agent-b")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tokenA, "sk-steiner-") {
		t.Fatalf("token format: %s", tokenA)
	}

	v, err := NewVerifier(keys)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := v.Lookup(tokenA); !ok || p != "agent-a" {
		t.Fatalf("lookup A = %q %v", p, ok)
	}
	if p, ok := v.Lookup(tokenB); !ok || p != "agent-b" {
		t.Fatalf("lookup B = %q %v", p, ok)
	}
	if _, ok := v.Lookup("sk-steiner-forged"); ok {
		t.Fatal("forged token accepted")
	}
}

func TestMissingKeysFileRejectsAll(t *testing.T) {
	v, err := NewVerifier(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Lookup("sk-steiner-x"); ok {
		t.Fatal("verifier without keys accepted a token")
	}
}

func TestMiddleware(t *testing.T) {
	keys := filepath.Join(t.TempDir(), "keys.yaml")
	token, err := Generate(keys, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(keys)
	if err != nil {
		t.Fatal(err)
	}

	var sawPrincipal string
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPrincipal, _ = PrincipalFrom(r.Context())
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth header: got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || sawPrincipal != "agent-a" {
		t.Fatalf("valid token: code=%d principal=%q", rec.Code, sawPrincipal)
	}
}
