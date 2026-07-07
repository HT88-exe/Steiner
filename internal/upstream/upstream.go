// Package upstream manages connections from the gateway to upstream MCP
// servers and keeps a synced snapshot of their tools, prompts, and resources.
package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/brueing/steiner/internal/config"
	"github.com/brueing/steiner/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Upstream is one connected upstream server plus its latest feature snapshot.
type Upstream struct {
	Name string
	cfg  config.Upstream

	session *mcp.ClientSession

	mu        sync.RWMutex
	tools     []*mcp.Tool
	prompts   []*mcp.Prompt
	resources []*mcp.Resource
	templates []*mcp.ResourceTemplate
}

// Manager owns all upstream connections.
type Manager struct {
	logger *slog.Logger

	// TransportFor overrides transport construction (used by tests to wire
	// in-memory upstreams). When nil, transports come from the config.
	TransportFor func(config.Upstream) (mcp.Transport, error)

	// OnChange is invoked after an upstream's feature list is re-synced.
	OnChange func()

	mu    sync.RWMutex
	ups   map[string]*Upstream
	order []string
}

// NewManager returns an empty manager.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{logger: logger, ups: map[string]*Upstream{}}
}

// Connect dials every configured upstream and performs the initial sync.
// A failing upstream aborts startup: silently missing tools would be worse.
func (m *Manager) Connect(ctx context.Context, upstreams []config.Upstream) error {
	for _, uc := range upstreams {
		up, err := m.dial(ctx, uc)
		if err != nil {
			return fmt.Errorf("upstream %q: %w", uc.Name, err)
		}
		if err := up.sync(ctx); err != nil {
			return fmt.Errorf("upstream %q: initial sync: %w", uc.Name, err)
		}
		m.mu.Lock()
		m.ups[uc.Name] = up
		m.order = append(m.order, uc.Name)
		m.mu.Unlock()
		m.logger.Info("upstream connected", "name", uc.Name, "tools", len(up.Tools()))
	}
	return nil
}

func (m *Manager) dial(ctx context.Context, uc config.Upstream) (*Upstream, error) {
	up := &Upstream{Name: uc.Name, cfg: uc}

	var transport mcp.Transport
	var err error
	if m.TransportFor != nil {
		transport, err = m.TransportFor(uc)
	} else {
		transport, err = transportFor(uc)
	}
	if err != nil {
		return nil, err
	}

	resync := func(what string) {
		if err := up.sync(context.Background()); err != nil {
			m.logger.Warn("resync failed", "upstream", uc.Name, "trigger", what, "err", err)
			return
		}
		m.logger.Info("upstream changed", "upstream", uc.Name, "trigger", what)
		if m.OnChange != nil {
			m.OnChange()
		}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "steiner", Version: version.Version}, &mcp.ClientOptions{
		Logger:                     m.logger.With("upstream", uc.Name),
		ToolListChangedHandler:     func(context.Context, *mcp.ToolListChangedRequest) { resync("tools") },
		PromptListChangedHandler:   func(context.Context, *mcp.PromptListChangedRequest) { resync("prompts") },
		ResourceListChangedHandler: func(context.Context, *mcp.ResourceListChangedRequest) { resync("resources") },
	})

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	up.session = session
	return up, nil
}

func transportFor(uc config.Upstream) (mcp.Transport, error) {
	switch uc.Transport {
	case "stdio":
		cmd := exec.Command(uc.Command, uc.Args...)
		cmd.Env = os.Environ()
		for k, v := range uc.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		cmd.Stderr = os.Stderr
		return &mcp.CommandTransport{Command: cmd}, nil
	case "http":
		client := http.DefaultClient
		if len(uc.Headers) > 0 {
			// Credentials live in gateway config; agents never see them.
			client = &http.Client{Transport: &headerTransport{base: http.DefaultTransport, headers: uc.Headers}}
		}
		return &mcp.StreamableClientTransport{Endpoint: uc.URL, HTTPClient: client}, nil
	default:
		return nil, fmt.Errorf("unknown transport %q", uc.Transport)
	}
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}

// sync refreshes the upstream's feature snapshot.
func (u *Upstream) sync(ctx context.Context) error {
	var (
		tools     []*mcp.Tool
		prompts   []*mcp.Prompt
		resources []*mcp.Resource
		templates []*mcp.ResourceTemplate
	)
	for t, err := range u.session.Tools(ctx, nil) {
		if err != nil {
			return err
		}
		tools = append(tools, t)
	}
	// Prompts, resources, and templates are optional capabilities; a method
	// error here means "not supported", which is fine.
	for p, err := range u.session.Prompts(ctx, nil) {
		if err != nil {
			break
		}
		prompts = append(prompts, p)
	}
	for r, err := range u.session.Resources(ctx, nil) {
		if err != nil {
			break
		}
		resources = append(resources, r)
	}
	for t, err := range u.session.ResourceTemplates(ctx, nil) {
		if err != nil {
			break
		}
		templates = append(templates, t)
	}

	u.mu.Lock()
	u.tools, u.prompts, u.resources, u.templates = tools, prompts, resources, templates
	u.mu.Unlock()
	return nil
}

// Tools returns the latest tool snapshot.
func (u *Upstream) Tools() []*mcp.Tool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.tools
}

// Prompts returns the latest prompt snapshot.
func (u *Upstream) Prompts() []*mcp.Prompt {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.prompts
}

// Resources returns the latest resource snapshot.
func (u *Upstream) Resources() []*mcp.Resource {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.resources
}

// Templates returns the latest resource template snapshot.
func (u *Upstream) Templates() []*mcp.ResourceTemplate {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.templates
}

// All returns the upstreams in stable (config) order.
func (m *Manager) All() []*Upstream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Upstream, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.ups[name])
	}
	return out
}

// Get returns one upstream by name.
func (m *Manager) Get(name string) (*Upstream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.ups[name]
	return u, ok
}

// CallTool forwards a tool call to the named upstream with raw arguments.
func (m *Manager) CallTool(ctx context.Context, upstream, tool string, args json.RawMessage) (*mcp.CallToolResult, error) {
	u, ok := m.Get(upstream)
	if !ok {
		return nil, fmt.Errorf("unknown upstream %q", upstream)
	}
	return u.session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
}

// GetPrompt forwards a prompt request to the named upstream.
func (m *Manager) GetPrompt(ctx context.Context, upstream, prompt string, args map[string]string) (*mcp.GetPromptResult, error) {
	u, ok := m.Get(upstream)
	if !ok {
		return nil, fmt.Errorf("unknown upstream %q", upstream)
	}
	return u.session.GetPrompt(ctx, &mcp.GetPromptParams{Name: prompt, Arguments: args})
}

// ReadResource forwards a resource read to the named upstream.
func (m *Manager) ReadResource(ctx context.Context, upstream, uri string) (*mcp.ReadResourceResult, error) {
	u, ok := m.Get(upstream)
	if !ok {
		return nil, fmt.Errorf("unknown upstream %q", upstream)
	}
	return u.session.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
}

// Close shuts down all upstream sessions.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, u := range m.ups {
		if err := u.session.Close(); err != nil {
			m.logger.Warn("closing upstream", "name", name, "err", err)
		}
	}
	m.ups = map[string]*Upstream{}
	m.order = nil
}
