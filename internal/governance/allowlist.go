package governance

import (
	"path"

	"github.com/HT88-exe/steiner/internal/config"
)

// ToolAllowed reports whether the principal may use the namespaced tool.
// Allow patterns (when present) gate inclusion; Deny patterns override.
func ToolAllowed(p config.Principal, tool string) bool {
	if len(p.Allow) > 0 && !matchAny(p.Allow, tool) {
		return false
	}
	return !matchAny(p.Deny, tool)
}

func matchAny(patterns []string, name string) bool {
	for _, pat := range patterns {
		// Tool names contain no '/', so path.Match implements plain globs.
		if ok, err := path.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

// MatchAny reports whether name matches any glob pattern. Exposed for the
// policy engine, which shares the same matching semantics.
func MatchAny(patterns []string, name string) bool { return matchAny(patterns, name) }
