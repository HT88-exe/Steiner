package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/HT88-exe/steiner/internal/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Ingress returns the authenticated MCP HTTP handler for /mcp.
func (g *Gateway) Ingress(verifier *auth.Verifier) http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		name, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			return nil // unreachable behind the middleware; SDK responds 400
		}
		principal, err := g.PrincipalFor(name)
		if err != nil {
			g.Logger.Warn("key maps to unknown principal", "principal", name)
			return nil
		}
		return g.NewServer(principal)
	}, &mcp.StreamableHTTPOptions{
		Logger:                     g.Logger,
		SessionTimeout:             g.Cfg.SessionTimeout(),
		DisableLocalhostProtection: g.Cfg.DisableLocalhostProtection,
	})

	var h http.Handler = streamable
	h = g.sessionOwnershipMiddleware(h)
	h = mcpHeadersMiddleware(h)
	return verifier.Middleware(h)
}

// sessionOwnershipMiddleware prevents a valid key from attaching to another
// principal's session: the Mcp-Session-Id is minted by the gateway, so we
// know which principal owns it.
func (g *Gateway) sessionOwnershipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			owner, known := g.SessionPrincipal(sid)
			principal, _ := auth.PrincipalFrom(r.Context())
			if known && owner != principal {
				http.Error(w, "session belongs to another principal", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// mcpHeadersMiddleware cross-checks the SEP-2243 routing headers
// (Mcp-Method, Mcp-Name) against the request body when a client sends them.
// Clients on spec revisions before 2026-07-28 omit them, which is fine; a
// mismatch is always an attack or a bug and is rejected.
func mcpHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hMethod := r.Header.Get("Mcp-Method")
		hName := r.Header.Get("Mcp-Name")
		if r.Method != http.MethodPost || (hMethod == "" && hName == "") {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		var msg struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
				URI  string `json:"uri"`
			} `json:"params"`
		}
		// Non-JSON or batch payloads are left to the SDK to reject.
		if err := json.Unmarshal(body, &msg); err == nil && msg.Method != "" {
			if hMethod != "" && hMethod != msg.Method {
				http.Error(w, "Mcp-Method header does not match body", http.StatusBadRequest)
				return
			}
			bodyName := msg.Params.Name
			if bodyName == "" {
				bodyName = msg.Params.URI
			}
			if hName != "" && bodyName != "" && hName != bodyName {
				http.Error(w, "Mcp-Name header does not match body", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ServeHTTP runs the MCP ingress and admin servers until ctx is canceled.
func (g *Gateway) ServeHTTP(ctx context.Context, verifier *auth.Verifier, admin http.Handler) error {
	if err := RequireLoopback(g.Cfg.AdminListen); err != nil {
		return err
	}

	ingressMux := http.NewServeMux()
	ingressMux.Handle("/mcp", g.Ingress(verifier))
	ingressSrv := &http.Server{Addr: g.Cfg.Listen, Handler: ingressMux}

	adminSrv := &http.Server{Addr: g.Cfg.AdminListen, Handler: admin}

	errc := make(chan error, 2)
	go func() {
		g.Logger.Info("mcp ingress listening", "addr", "http://"+g.Cfg.Listen+"/mcp")
		errc <- ingressSrv.ListenAndServe()
	}()
	go func() {
		g.Logger.Info("admin api listening", "addr", "http://"+g.Cfg.AdminListen)
		errc <- adminSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ingressSrv.Shutdown(shutdownCtx)
		_ = adminSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// RequireLoopback ensures the admin API only binds to loopback addresses.
func RequireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin_listen %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("admin_listen %q must be a loopback address", addr)
	}
	return nil
}
