package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HT88-exe/steiner/internal/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type authedTransport struct {
	token string
	base  http.RoundTripper
}

func (t *authedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// TestHTTPIngress runs the real wire path: StreamableClientTransport ->
// auth middleware -> streamable handler -> pipeline -> in-memory upstream.
func TestHTTPIngress(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	gw := newTestGateway(t, ctx, cfg)

	keysPath := filepath.Join(t.TempDir(), "keys.yaml")
	token, err := auth.Generate(keysPath, "tester")
	if err != nil {
		t.Fatal(err)
	}
	// Second key for the hijack check below; both must exist before the
	// verifier snapshots the keys file.
	otherToken, err := auth.Generate(keysPath, "other")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewVerifier(keysPath)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(gw.Ingress(verifier))
	defer ts.Close()

	// Unauthenticated requests are rejected before touching MCP.
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST: got %d, want 401", resp.StatusCode)
	}

	// Authenticated MCP session works end to end.
	client := mcp.NewClient(&mcp.Implementation{Name: "http-client", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: &authedTransport{token: token, base: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "web_echo", Arguments: map[string]any{"via": "http"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || !strings.Contains(resText(res), "http") {
		t.Fatalf("echo over HTTP failed: %q", resText(res))
	}

	// Session hijack protection: a different principal's key cannot reuse
	// this session ID.
	sid := cs.ID()
	if sid == "" {
		t.Fatal("expected a session ID over HTTP")
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sid)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("hijack attempt: got %d, want 403", resp2.StatusCode)
	}
}

func TestMcpHeadersMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := mcpHeadersMiddleware(inner)

	post := func(headers map[string]string, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_echo"}}`

	if code := post(nil, body); code != http.StatusOK {
		t.Fatalf("no headers must pass through: %d", code)
	}
	if code := post(map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "web_echo"}, body); code != http.StatusOK {
		t.Fatalf("matching headers must pass: %d", code)
	}
	if code := post(map[string]string{"Mcp-Method": "resources/read"}, body); code != http.StatusBadRequest {
		t.Fatalf("method mismatch must 400: %d", code)
	}
	if code := post(map[string]string{"Mcp-Name": "other_tool"}, body); code != http.StatusBadRequest {
		t.Fatalf("name mismatch must 400: %d", code)
	}
}

func TestRequireLoopback(t *testing.T) {
	if err := requireLoopback("127.0.0.1:8386"); err != nil {
		t.Fatal(err)
	}
	if err := requireLoopback("localhost:8386"); err != nil {
		t.Fatal(err)
	}
	if err := requireLoopback("0.0.0.0:8386"); err == nil {
		t.Fatal("0.0.0.0 must be rejected for the admin API")
	}
}
