// Package policy implements Steiner's containment policy engine.
//
// The engine is deterministic: given a session's taint state and a proposed
// tool call, it either allows the call, blocks it with a reason, or requires
// human approval. Detection heuristics (package detect) only feed signals in;
// enforcement happens here.
package policy

import (
	"fmt"
	"regexp"

	"github.com/brueing/steiner/internal/config"
	"github.com/brueing/steiner/internal/detect"
	"github.com/brueing/steiner/internal/dlp"
	"github.com/brueing/steiner/internal/governance"
)

// Verdict is the engine's decision for one call.
type Verdict struct {
	// Action is "allow", "deny", or "approve" (human approval required).
	Action string
	// Code is a stable machine-readable decision code for audit.
	Code string
	// Reason is the human-readable explanation.
	Reason string
	// Flags are non-blocking signals worth auditing.
	Flags []string
}

func allow(flags []string) Verdict { return Verdict{Action: "allow", Code: "allowed", Flags: flags} }
func deny(code, reason string, flags []string) Verdict {
	return Verdict{Action: "deny", Code: code, Reason: reason, Flags: flags}
}

// Engine evaluates calls against a config.Policy.
type Engine struct {
	cfg      *config.Policy
	argRules []compiledRule
	det      *detect.Detectors
}

type compiledRule struct {
	id     string
	re     *regexp.Regexp
	action string
}

// New builds an engine. Both cfg and det may be nil, disabling their checks.
func New(cfg *config.Policy, det *detect.Detectors) *Engine {
	e := &Engine{cfg: cfg, det: det}
	if cfg != nil {
		for _, r := range cfg.ArgRules {
			e.argRules = append(e.argRules, compiledRule{
				id: r.ID,
				// Patterns are validated at config load.
				re:     regexp.MustCompile(r.Pattern),
				action: r.Action,
			})
		}
	}
	return e
}

// TaintsSession reports whether calling tool marks the session as having
// read untrusted content.
func (e *Engine) TaintsSession(tool string) bool {
	return e.cfg != nil && governance.MatchAny(e.cfg.UntrustedSources, tool)
}

// IsExternalSink reports whether tool can exfiltrate data.
func (e *Engine) IsExternalSink(tool string) bool {
	return e.cfg != nil && governance.MatchAny(e.cfg.ExternalSinks, tool)
}

// EvaluateCall decides whether a tool call may proceed.
// args is the raw JSON of the outbound tool arguments; tainted is the
// session's current taint state.
func (e *Engine) EvaluateCall(tool string, args string, tainted bool) Verdict {
	var flags []string

	// Detector signals come first so even allowed calls carry their flags.
	if e.det != nil {
		sig := e.det.ScanArgs(args)
		flags = append(flags, sig.Flags...)
		if sig.BlockReason != "" {
			return deny("denied_detector", sig.BlockReason, flags)
		}
	}

	if e.cfg == nil {
		return allow(flags)
	}

	// The trifecta rule: a session that has read untrusted content may not
	// reach tools with external side effects. This is the containment core --
	// it does not matter whether an injection was detected.
	if tainted && e.IsExternalSink(tool) &&
		(e.cfg.BlockSinksWhenTainted == nil || *e.cfg.BlockSinksWhenTainted) {
		return deny("denied_tainted_sink",
			fmt.Sprintf("session has read untrusted content; calls to external sink %q are blocked", tool), flags)
	}

	// Built-in DLP over outbound arguments.
	if e.cfg.BlockSecretsInArgs {
		if ids := dlp.Scan(args); len(ids) > 0 {
			return deny("denied_dlp",
				fmt.Sprintf("arguments contain sensitive data (%v)", ids), flags)
		}
	}

	// Custom argument rules.
	for _, r := range e.argRules {
		if r.re.MatchString(args) {
			if r.action == "block" {
				return deny("denied_arg_rule", fmt.Sprintf("argument rule %q matched", r.id), flags)
			}
			flags = append(flags, "arg_rule:"+r.id)
		}
	}

	if governance.MatchAny(e.cfg.RequireApproval, tool) {
		return Verdict{Action: "approve", Code: "approval_required",
			Reason: fmt.Sprintf("tool %q requires human approval", tool), Flags: flags}
	}

	return allow(flags)
}

// EvaluateResult inspects a tool result and reports whether the session
// should be tainted, with the reason.
func (e *Engine) EvaluateResult(tool string, resultText string) (taint bool, reason string, flags []string) {
	if e.TaintsSession(tool) {
		return true, fmt.Sprintf("read untrusted content via %q", tool), nil
	}
	if e.det != nil {
		if hit := e.det.InjectionPhrase(resultText); hit != "" {
			return true, fmt.Sprintf("injection phrasing in %q result (%s)", tool, hit), []string{"injection_phrase:" + hit}
		}
	}
	return false, "", nil
}
