// Package gateway builds the virtual MCP server that agents connect to and
// runs every call through the enforcement pipeline:
//
//	allowlist -> rate limit -> policy (taint/DLP/approval) -> forward -> audit
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/brueing/steiner/internal/audit"
	"github.com/brueing/steiner/internal/config"
	"github.com/brueing/steiner/internal/detect"
	"github.com/brueing/steiner/internal/governance"
	"github.com/brueing/steiner/internal/policy"
	"github.com/brueing/steiner/internal/upstream"
	"github.com/brueing/steiner/internal/version"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Gateway wires config, upstreams, and enforcement together.
type Gateway struct {
	Cfg     *config.Config
	Ups     *upstream.Manager
	Audit   *audit.Log
	Broker  *policy.Broker
	Engine  *policy.Engine
	Limiter *governance.Limiter
	Logger  *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session // audit session key -> session
}

// New assembles a Gateway from loaded config and connected upstreams.
func New(cfg *config.Config, ups *upstream.Manager, log *audit.Log, logger *slog.Logger) *Gateway {
	det := detect.New(cfg.Detectors)
	g := &Gateway{
		Cfg:      cfg,
		Ups:      ups,
		Audit:    log,
		Broker:   policy.NewBroker(cfg.Notifications.SlackWebhookURL),
		Engine:   policy.New(cfg.Policy, det),
		Limiter:  governance.NewLimiter(),
		Logger:   logger,
		sessions: map[string]*session{},
	}
	ups.OnChange = g.rebuildAll
	return g
}

// session is the gateway-side state for one downstream MCP session.
type session struct {
	key       string
	principal config.Principal
	server    *mcp.Server
	created   time.Time

	mu          sync.Mutex
	tainted     bool
	taintReason string
	// registered tracks feature keys ("t:<name>", "p:<name>") currently
	// registered on the server, so upstream changes can remove stale ones.
	registered map[string]bool
}

func (s *session) isTainted() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tainted, s.taintReason
}

func (s *session) taint(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tainted {
		s.tainted = true
		s.taintReason = reason
	}
}

// NewServer builds the virtual MCP server for one downstream session owned
// by the given principal. Each session gets its own server instance so taint
// state is naturally session-scoped.
func (g *Gateway) NewServer(principal config.Principal) *mcp.Server {
	sess := &session{
		key:       strings.ReplaceAll(uuid.NewString(), "-", "")[:16],
		principal: principal,
		created:   time.Now(),
	}

	instructions := g.Cfg.Instructions
	if instructions == "" {
		instructions = "Steiner is a security gateway. Tools are namespaced as <upstream>_<tool>. " +
			"Calls may be denied by policy; a denial is not a tool malfunction, so explain it to the user instead of retrying."
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "steiner", Title: "Steiner Gateway", Version: version.Version}, &mcp.ServerOptions{
		Instructions: instructions,
		Logger:       g.Logger.With("session", sess.key, "principal", principal.Name),
		// The gateway mints session IDs so the HTTP Mcp-Session-Id header and
		// the audit session_key are the same string. Taint state is keyed on
		// gateway identity, never on protocol session state (which the
		// 2026-07-28 MCP revision removes).
		GetSessionID: func() string { return sess.key },
		InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
			g.record(&audit.Event{
				SessionKey: sess.key, Principal: principal.Name,
				Method: "initialized", Decision: "session_start",
			})
		},
	})
	sess.server = srv

	g.registerFeatures(sess)

	g.mu.Lock()
	g.sessions[sess.key] = sess
	g.mu.Unlock()
	return srv
}

// registerFeatures syncs the session's server with the current upstream
// snapshots: registers namespaced features (filtered by the principal's
// allowlist) and removes ones that no longer exist. The SDK emits
// list_changed notifications downstream as a result.
func (g *Gateway) registerFeatures(sess *session) {
	reg := map[string]bool{}
	for _, up := range g.Ups.All() {
		upName := up.Name
		for _, t := range up.Tools() {
			nsName := upName + "_" + t.Name
			if !governance.ToolAllowed(sess.principal, nsName) {
				continue
			}
			nt := *t
			nt.Name = nsName
			if nt.InputSchema == nil {
				nt.InputSchema = map[string]any{"type": "object"}
			}
			sess.server.AddTool(&nt, g.toolHandler(sess, upName, t.Name, nsName))
			reg["t:"+nsName] = true
		}
		for _, p := range up.Prompts() {
			np := *p
			np.Name = upName + "_" + p.Name
			sess.server.AddPrompt(&np, g.promptHandler(sess, upName, p.Name, np.Name))
			reg["p:"+np.Name] = true
		}
		for _, r := range up.Resources() {
			nr := *r
			sess.server.AddResource(&nr, g.resourceHandler(sess, upName))
		}
		for _, t := range up.Templates() {
			nt := *t
			sess.server.AddResourceTemplate(&nt, g.resourceHandler(sess, upName))
		}
	}

	sess.mu.Lock()
	prev := sess.registered
	sess.registered = reg
	sess.mu.Unlock()

	var staleTools, stalePrompts []string
	for name := range prev {
		if reg[name] {
			continue
		}
		kind, n, _ := strings.Cut(name, ":")
		switch kind {
		case "t":
			staleTools = append(staleTools, n)
		case "p":
			stalePrompts = append(stalePrompts, n)
		}
	}
	if len(staleTools) > 0 {
		sess.server.RemoveTools(staleTools...)
	}
	if len(stalePrompts) > 0 {
		sess.server.RemovePrompts(stalePrompts...)
	}
}

// rebuildAll re-syncs every live session's features after an upstream
// list_changed notification, and prunes state for closed sessions.
func (g *Gateway) rebuildAll() {
	g.mu.Lock()
	sessions := make([]*session, 0, len(g.sessions))
	for key, s := range g.sessions {
		// Grace period: a just-created server has no SDK session until the
		// client finishes initializing.
		if s.sessionCount() == 0 && time.Since(s.created) > time.Minute {
			delete(g.sessions, key)
			continue
		}
		sessions = append(sessions, s)
	}
	g.mu.Unlock()

	for _, s := range sessions {
		g.registerFeatures(s)
	}
}

func (s *session) sessionCount() int {
	n := 0
	for range s.server.Sessions() {
		n++
	}
	return n
}

// record writes an audit event, logging (rather than failing the call) on
// audit errors.
func (g *Gateway) record(e *audit.Event) {
	if err := g.Audit.Record(e); err != nil {
		g.Logger.Error("audit write failed", "err", err)
	}
}

// denied produces the CallToolResult for a blocked call. Denials are tool
// results (not protocol errors) so the model can read the reason, adapt, and
// explain to the user.
func denied(reason string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "Steiner blocked this call: " + reason}},
	}
}

// toolHandler returns the enforcement pipeline for one namespaced tool.
func (g *Gateway) toolHandler(sess *session, upName, origName, nsName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		args := string(req.Params.Arguments)
		tainted, _ := sess.isTainted()
		ev := &audit.Event{
			SessionKey: sess.key,
			Principal:  sess.principal.Name,
			Upstream:   upName,
			Tool:       nsName,
			Method:     "tools/call",
			Args:       args,
			Tainted:    tainted,
		}
		finish := func(decision, reason string) {
			ev.Decision, ev.Reason = decision, reason
			ev.LatencyMS = time.Since(start).Milliseconds()
			g.record(ev)
		}

		// Defense in depth: disallowed tools are never registered, but the
		// allowlist is cheap to re-check.
		if !governance.ToolAllowed(sess.principal, nsName) {
			finish("denied_allowlist", "tool not in principal allowlist")
			return denied("tool not permitted for this principal"), nil
		}
		if code, reason, ok := g.Limiter.Allow(sess.principal); !ok {
			finish(code, reason)
			return denied(reason), nil
		}

		verdict := g.Engine.EvaluateCall(nsName, args, tainted)
		ev.Flags = verdict.Flags
		switch verdict.Action {
		case "deny":
			finish(verdict.Code, verdict.Reason)
			return denied(verdict.Reason), nil
		case "approve":
			approved, how := g.requestApproval(ctx, sess, req, nsName, args, verdict.Reason)
			if !approved {
				finish("denied_approval", how)
				return denied("approval was not granted: " + how), nil
			}
			ev.Flags = append(ev.Flags, "approved")
		}

		res, err := g.Ups.CallTool(ctx, upName, origName, req.Params.Arguments)
		if err != nil {
			finish("upstream_error", err.Error())
			return nil, fmt.Errorf("upstream %q: %w", upName, err)
		}

		text := resultText(res)
		if taint, reason, flags := g.Engine.EvaluateResult(nsName, text); taint {
			sess.taint(reason)
			ev.Flags = append(ev.Flags, flags...)
			ev.Tainted = true
		}
		ev.ResultDigest = audit.Digest([]byte(text))
		ev.ResultLen = len(text)
		finish("allowed", "")
		return res, nil
	}
}

// requestApproval tries MCP elicitation (in-client prompt) first, falling
// back to the admin approval queue.
func (g *Gateway) requestApproval(ctx context.Context, sess *session, req *mcp.CallToolRequest, tool, args, why string) (bool, string) {
	timeout := 120 * time.Second
	if g.Cfg.Policy != nil {
		timeout = g.Cfg.Policy.ApprovalTimeout()
	}

	if supportsElicitation(req) {
		res, err := req.Session.Elicit(ctx, &mcp.ElicitParams{
			Mode: "form",
			Message: fmt.Sprintf("Steiner: approve tool call?\n\ntool: %s\nprincipal: %s\narguments: %s\nreason: %s",
				tool, sess.principal.Name, truncate(args, 800), why),
			RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		})
		if err == nil {
			if res.Action == "accept" {
				return true, "approved via client elicitation"
			}
			return false, "declined via client elicitation"
		}
		g.Logger.Warn("elicitation failed; falling back to approval queue", "err", err)
	}

	return g.Broker.Request(ctx, sess.principal.Name, tool, args, why, timeout)
}

func supportsElicitation(req *mcp.CallToolRequest) bool {
	if req.Session == nil {
		return false
	}
	params := req.Session.InitializeParams()
	return params != nil && params.Capabilities != nil && params.Capabilities.Elicitation != nil
}

// promptHandler forwards prompts/get with auditing.
func (g *Gateway) promptHandler(sess *session, upName, origName, nsName string) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		start := time.Now()
		res, err := g.Ups.GetPrompt(ctx, upName, origName, req.Params.Arguments)
		ev := &audit.Event{
			SessionKey: sess.key, Principal: sess.principal.Name, Upstream: upName,
			Tool: nsName, Method: "prompts/get", Decision: "allowed",
			LatencyMS: time.Since(start).Milliseconds(),
		}
		if err != nil {
			ev.Decision, ev.Reason = "upstream_error", err.Error()
		}
		g.record(ev)
		return res, err
	}
}

// resourceHandler forwards resources/read with auditing. Resource reads are
// audited but not policy-gated in v1 (see README limitations).
func (g *Gateway) resourceHandler(sess *session, upName string) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		start := time.Now()
		res, err := g.Ups.ReadResource(ctx, upName, req.Params.URI)
		ev := &audit.Event{
			SessionKey: sess.key, Principal: sess.principal.Name, Upstream: upName,
			Tool: req.Params.URI, Method: "resources/read", Decision: "allowed",
			LatencyMS: time.Since(start).Milliseconds(),
		}
		if err != nil {
			ev.Decision, ev.Reason = "upstream_error", err.Error()
		}
		g.record(ev)
		return res, err
	}
}

// resultText flattens a tool result's text content for taint evaluation and
// digesting.
func resultText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString("\n")
		}
	}
	if res.StructuredContent != nil {
		if j, err := json.Marshal(res.StructuredContent); err == nil {
			b.Write(j)
		}
	}
	return b.String()
}

// PrincipalFor resolves a principal by name from config.
func (g *Gateway) PrincipalFor(name string) (config.Principal, error) {
	p, ok := g.Cfg.Principal(name)
	if !ok {
		return config.Principal{}, fmt.Errorf("principal %q is not configured", name)
	}
	return p, nil
}

// SessionPrincipal reports which principal owns a live session key, for
// hijack checks at the HTTP layer.
func (g *Gateway) SessionPrincipal(key string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[key]
	if !ok {
		return "", false
	}
	return s.principal.Name, true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
