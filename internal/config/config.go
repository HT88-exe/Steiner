// Package config loads and validates the Steiner gateway configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration document (steiner.yaml).
type Config struct {
	// Listen is the address for the MCP ingress endpoint (/mcp).
	Listen string `yaml:"listen"`
	// AdminListen is the address for the admin API and trace viewer.
	// It must resolve to a loopback address.
	AdminListen string `yaml:"admin_listen"`
	// AdminKey optionally protects the admin API with a bearer token.
	AdminKey string `yaml:"admin_key"`
	// KeysFile stores hashed client API keys (managed by `steiner keygen`).
	KeysFile string `yaml:"keys_file"`
	// AuditDB is the path of the append-only SQLite audit database.
	AuditDB string `yaml:"audit_db"`
	// Instructions is advertised to connecting MCP clients.
	Instructions string `yaml:"instructions"`
	// DefaultPrincipal names the principal used for stdio ingress, where
	// there is no HTTP authentication. Defaults to "local".
	DefaultPrincipal string `yaml:"default_principal"`
	// SessionTimeoutMinutes closes idle downstream sessions. Default 30.
	SessionTimeoutMinutes int `yaml:"session_timeout_minutes"`
	// DisableLocalhostProtection passes through the SDK's DNS-rebinding
	// protection toggle. Leave false unless you know what you are doing.
	DisableLocalhostProtection bool `yaml:"disable_localhost_protection"`

	Upstreams  []Upstream  `yaml:"upstreams"`
	Principals []Principal `yaml:"principals"`
	Policy     *Policy     `yaml:"policy"`
	Detectors  Detectors   `yaml:"detectors"`

	Notifications Notifications `yaml:"notifications"`

	// dir is the directory containing the config file, used to resolve
	// relative paths.
	dir string
}

// Upstream declares one upstream MCP server.
type Upstream struct {
	// Name namespaces the upstream's tools ("<name>_<tool>"). It must match
	// ^[a-z0-9][a-z0-9-]*$ so namespaced tool names remain spec-valid.
	Name string `yaml:"name"`
	// Transport is "stdio" or "http".
	Transport string `yaml:"transport"`

	// Stdio transport fields.
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`

	// HTTP transport fields. Headers lets the gateway hold upstream
	// credentials so agents never see them.
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}

// Principal is an identity that may connect through the gateway.
type Principal struct {
	Name string `yaml:"name"`
	// Allow lists glob patterns over namespaced tool names. Empty = all.
	Allow []string `yaml:"allow"`
	// Deny lists glob patterns that override Allow.
	Deny []string `yaml:"deny"`
	// RateLimit constrains tool-call volume.
	RateLimit *RateLimit `yaml:"rate_limit"`
}

// RateLimit uses fixed windows so audit messages are predictable.
type RateLimit struct {
	PerMinute int `yaml:"per_minute"`
	PerDay    int `yaml:"per_day"`
}

// Policy is the containment policy document.
type Policy struct {
	// UntrustedSources are tool globs whose results are untrusted content.
	// Calling one taints the session.
	UntrustedSources []string `yaml:"untrusted_sources"`
	// ExternalSinks are tool globs with external side effects (exfiltration
	// channels).
	ExternalSinks []string `yaml:"external_sinks"`
	// BlockSinksWhenTainted is the "lethal trifecta" rule: a tainted session
	// may not call external sinks. Defaults to true when a policy is present.
	BlockSinksWhenTainted *bool `yaml:"block_sinks_when_tainted"`
	// BlockSecretsInArgs blocks calls whose arguments contain likely
	// credentials or PII (built-in DLP patterns).
	BlockSecretsInArgs bool `yaml:"block_secrets_in_args"`
	// ArgRules are custom DLP rules applied to outbound tool arguments.
	ArgRules []ArgRule `yaml:"arg_rules"`
	// RequireApproval lists tool globs that need human approval per call.
	RequireApproval []string `yaml:"require_approval"`
	// ApprovalTimeoutSeconds bounds how long a call waits for approval
	// before being denied. Default 120.
	ApprovalTimeoutSeconds int `yaml:"approval_timeout_seconds"`
}

// ArgRule is a custom pattern rule over outbound tool arguments.
type ArgRule struct {
	ID      string `yaml:"id"`
	Pattern string `yaml:"pattern"`
	// Action is "block" or "flag".
	Action string `yaml:"action"`
}

// Detectors configures heuristic signals layered on top of policy.
type Detectors struct {
	// FlagBase64Blobs flags long high-entropy base64 runs in outbound
	// arguments (a common exfiltration encoding).
	FlagBase64Blobs bool `yaml:"flag_base64_blobs"`
	// FlagNewDomains flags never-before-seen domains in outbound arguments.
	FlagNewDomains bool `yaml:"flag_new_domains"`
	// BlockNewDomains upgrades the new-domain flag to a denial.
	BlockNewDomains bool `yaml:"block_new_domains"`
	// TaintOnInjectionPhrases taints the session when a tool result contains
	// known injection phrasing, regardless of source classification.
	TaintOnInjectionPhrases bool `yaml:"taint_on_injection_phrases"`
}

// Notifications configures human-in-the-loop side channels.
type Notifications struct {
	// SlackWebhookURL receives approval requests and policy denials.
	SlackWebhookURL string `yaml:"slack_webhook_url"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// Load reads, validates, and applies defaults to a config file.
func Load(cfgPath string) (*Config, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // fail loudly on typo'd keys
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", cfgPath, err)
	}
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return nil, err
	}
	c.dir = filepath.Dir(abs)
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", cfgPath, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8385"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:8386"
	}
	if c.KeysFile == "" {
		c.KeysFile = "steiner.keys.yaml"
	}
	if c.AuditDB == "" {
		c.AuditDB = "steiner-audit.db"
	}
	if c.DefaultPrincipal == "" {
		c.DefaultPrincipal = "local"
	}
	if c.SessionTimeoutMinutes == 0 {
		c.SessionTimeoutMinutes = 30
	}
	if len(c.Principals) == 0 {
		c.Principals = []Principal{{Name: "local"}}
	}
	if c.Policy != nil {
		if c.Policy.BlockSinksWhenTainted == nil {
			t := true
			c.Policy.BlockSinksWhenTainted = &t
		}
		if c.Policy.ApprovalTimeoutSeconds == 0 {
			c.Policy.ApprovalTimeoutSeconds = 120
		}
	}
}

func (c *Config) validate() error {
	seen := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if !nameRE.MatchString(u.Name) {
			return fmt.Errorf("upstream name %q must match %s", u.Name, nameRE)
		}
		if seen[u.Name] {
			return fmt.Errorf("duplicate upstream name %q", u.Name)
		}
		seen[u.Name] = true
		switch u.Transport {
		case "stdio":
			if u.Command == "" {
				return fmt.Errorf("upstream %q: stdio transport requires command", u.Name)
			}
		case "http":
			if u.URL == "" {
				return fmt.Errorf("upstream %q: http transport requires url", u.Name)
			}
		default:
			return fmt.Errorf("upstream %q: transport must be stdio or http, got %q", u.Name, u.Transport)
		}
	}
	seenP := map[string]bool{}
	for _, p := range c.Principals {
		if p.Name == "" {
			return fmt.Errorf("principal with empty name")
		}
		if seenP[p.Name] {
			return fmt.Errorf("duplicate principal %q", p.Name)
		}
		seenP[p.Name] = true
		if err := validGlobs("principal "+p.Name, append(p.Allow, p.Deny...)); err != nil {
			return err
		}
	}
	if c.Policy != nil {
		for _, r := range c.Policy.ArgRules {
			if r.Action != "block" && r.Action != "flag" {
				return fmt.Errorf("arg_rule %q: action must be block or flag", r.ID)
			}
			if _, err := regexp.Compile(r.Pattern); err != nil {
				return fmt.Errorf("arg_rule %q: %w", r.ID, err)
			}
		}
		globSets := [][]string{c.Policy.UntrustedSources, c.Policy.ExternalSinks, c.Policy.RequireApproval}
		for _, gs := range globSets {
			if err := validGlobs("policy", gs); err != nil {
				return err
			}
		}
	}
	return nil
}

func validGlobs(where string, patterns []string) error {
	for _, pat := range patterns {
		if _, err := path.Match(pat, "probe"); err != nil {
			return fmt.Errorf("%s: bad glob pattern %q", where, pat)
		}
	}
	return nil
}

// Principal returns the principal by name, if configured.
func (c *Config) Principal(name string) (Principal, bool) {
	for _, p := range c.Principals {
		if p.Name == name {
			return p, true
		}
	}
	return Principal{}, false
}

// ResolvePath resolves a possibly-relative path against the config file dir.
func (c *Config) ResolvePath(p string) string {
	if filepath.IsAbs(p) || c.dir == "" {
		return p
	}
	return filepath.Join(c.dir, p)
}

// SessionTimeout returns the idle session timeout as a duration.
func (c *Config) SessionTimeout() time.Duration {
	return time.Duration(c.SessionTimeoutMinutes) * time.Minute
}

// ApprovalTimeout returns the approval wait bound.
func (p *Policy) ApprovalTimeout() time.Duration {
	return time.Duration(p.ApprovalTimeoutSeconds) * time.Second
}

// Starter is the annotated starter config written by `steiner init`.
const Starter = `# Steiner MCP security gateway configuration.
# Agents connect to Steiner as a single MCP server; Steiner connects to the
# upstreams below and enforces policy on every call.

listen: 127.0.0.1:8385
admin_listen: 127.0.0.1:8386

# Upstream MCP servers to aggregate. Tool names are exposed as
# "<name>_<tool>", e.g. fs_read_file.
upstreams:
  - name: fs
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "."]
  # - name: linear
  #   transport: http
  #   url: https://mcp.linear.app/mcp
  #   headers:
  #     Authorization: "Bearer YOUR_TOKEN"   # vaulted: agents never see this

# Identities. Create keys with: steiner keygen --name agent-a
principals:
  - name: local            # used for --stdio ingress (no HTTP auth)
  - name: agent-a
    allow: ["fs_*"]
    deny: ["fs_write_file", "fs_move_file"]
    rate_limit: { per_minute: 60, per_day: 2000 }

# Containment policy: assume the model can be injected; make it non-catastrophic.
policy:
  # Tool results from these are untrusted content: calling one taints the session.
  untrusted_sources: ["web_*", "fetch_*", "browser_*"]
  # These tools can exfiltrate data. A tainted session may not call them.
  external_sinks: ["mail_*", "slack_*", "*_send", "*_post", "*_publish"]
  block_sinks_when_tainted: true            # the "lethal trifecta" rule
  block_secrets_in_args: true               # built-in DLP on outbound args
  require_approval: ["shell_*", "*_execute"]
  approval_timeout_seconds: 120
  arg_rules:
    - id: no-ssn
      pattern: '\b\d{3}-\d{2}-\d{4}\b'
      action: block

detectors:
  flag_base64_blobs: true
  flag_new_domains: true
  block_new_domains: false
  taint_on_injection_phrases: true

notifications:
  slack_webhook_url: ""
`
