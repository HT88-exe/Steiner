// Package policytest runs attack-scenario fixtures against a config's
// policy engine, deterministically and offline. It powers
// `steiner policy test` and doubles as the public containment eval.
package policytest

import (
	"fmt"
	"io"
	"os"

	"github.com/HT88-exe/steiner/internal/config"
	"github.com/HT88-exe/steiner/internal/detect"
	"github.com/HT88-exe/steiner/internal/policy"
	"gopkg.in/yaml.v3"
)

// File is a scenario fixture document.
type File struct {
	Scenarios []Scenario `yaml:"scenarios"`
}

// Scenario is an ordered sequence of simulated tool calls in one session.
type Scenario struct {
	Name  string `yaml:"name"`
	Steps []Step `yaml:"steps"`
}

// Step simulates one tool call.
type Step struct {
	// Call is the namespaced tool name (e.g. "web_fetch").
	Call string `yaml:"call"`
	// Args is the raw argument JSON the agent would send.
	Args string `yaml:"args"`
	// Result optionally simulates the tool's response text, which feeds
	// taint evaluation exactly like a live result would.
	Result string `yaml:"result"`
	// Expect is "allow", "deny", or "approve".
	Expect string `yaml:"expect"`
}

// Run executes the fixture at path against the given config, writing a
// report to w. It returns an error if any scenario fails.
func Run(cfg *config.Config, path string, w io.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(f.Scenarios) == 0 {
		return fmt.Errorf("%s contains no scenarios", path)
	}

	failed := 0
	for _, sc := range f.Scenarios {
		if err := runScenario(cfg, sc, w); err != nil {
			failed++
			fmt.Fprintf(w, "FAIL  %s\n      %v\n", sc.Name, err)
		} else {
			fmt.Fprintf(w, "pass  %s\n", sc.Name)
		}
	}
	fmt.Fprintf(w, "\n%d/%d scenarios passed\n", len(f.Scenarios)-failed, len(f.Scenarios))
	if failed > 0 {
		return fmt.Errorf("%d scenario(s) failed", failed)
	}
	return nil
}

func runScenario(cfg *config.Config, sc Scenario, w io.Writer) error {
	// Fresh engine and detector state per scenario keeps runs deterministic.
	eng := policy.New(cfg.Policy, detect.New(cfg.Detectors))
	tainted := false

	for i, step := range sc.Steps {
		if step.Call == "" {
			return fmt.Errorf("step %d: missing call", i+1)
		}
		verdict := eng.EvaluateCall(step.Call, step.Args, tainted)
		if step.Expect != "" && verdict.Action != step.Expect {
			return fmt.Errorf("step %d (%s): expected %q, got %q (%s)",
				i+1, step.Call, step.Expect, verdict.Action, verdict.Reason)
		}
		// Denied calls never reach the upstream, so their simulated results
		// must not affect taint state.
		if verdict.Action == "deny" {
			continue
		}
		if taint, _, _ := eng.EvaluateResult(step.Call, step.Result); taint {
			tainted = true
		}
	}
	return nil
}
