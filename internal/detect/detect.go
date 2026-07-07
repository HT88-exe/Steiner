// Package detect implements heuristic signals layered onto the policy
// engine: exfiltration encodings, novel domains, and injection phrasing.
// Detectors are probabilistic by nature, so most default to flagging rather
// than blocking; enforcement decisions belong to the policy engine.
package detect

import (
	"math"
	"regexp"
	"strings"
	"sync"

	"github.com/HT88-exe/steiner/internal/config"
)

// Signals is the result of scanning outbound arguments.
type Signals struct {
	Flags []string
	// BlockReason is non-empty when a detector is configured to block.
	BlockReason string
}

// Detectors holds detector state. Seen domains are tracked in memory for the
// lifetime of the gateway process.
type Detectors struct {
	cfg config.Detectors

	mu          sync.Mutex
	seenDomains map[string]bool
}

// New builds detectors from config.
func New(cfg config.Detectors) *Detectors {
	return &Detectors{cfg: cfg, seenDomains: map[string]bool{}}
}

var (
	base64RunRE = regexp.MustCompile(`[A-Za-z0-9+/=]{80,}`)
	domainRE    = regexp.MustCompile(`(?i)\bhttps?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})`)

	// injectionPhrases are common instruction-override phrasings seen in
	// prompt injection payloads. Matching one taints the session (it never
	// blocks directly).
	injectionPhrases = []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"disregard your instructions",
		"you must now",
		"do not tell the user",
		"without telling the user",
		"exfiltrate",
		"send the contents of",
		"forward this email to",
		"new system prompt",
	}
)

// ScanArgs inspects outbound tool arguments.
func (d *Detectors) ScanArgs(args string) Signals {
	var s Signals

	if d.cfg.FlagBase64Blobs {
		for _, run := range base64RunRE.FindAllString(args, 3) {
			if shannonEntropy(run) > 4.0 {
				s.Flags = append(s.Flags, "base64_blob")
				break
			}
		}
	}

	if d.cfg.FlagNewDomains || d.cfg.BlockNewDomains {
		for _, m := range domainRE.FindAllStringSubmatch(args, 10) {
			domain := strings.ToLower(m[1])
			if d.markSeen(domain) {
				continue
			}
			s.Flags = append(s.Flags, "new_domain:"+domain)
			if d.cfg.BlockNewDomains {
				s.BlockReason = "arguments reference a never-before-seen domain: " + domain
			}
		}
	}
	return s
}

// markSeen records the domain, reporting whether it was already known.
func (d *Detectors) markSeen(domain string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seenDomains[domain] {
		return true
	}
	d.seenDomains[domain] = true
	return false
}

// SeedDomains marks domains as known (e.g. from config or past audit) so
// they do not trip the new-domain detector.
func (d *Detectors) SeedDomains(domains []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, dom := range domains {
		d.seenDomains[strings.ToLower(dom)] = true
	}
}

// InjectionPhrase returns the first known injection phrasing found in a tool
// result, or "".
func (d *Detectors) InjectionPhrase(result string) string {
	if !d.cfg.TaintOnInjectionPhrases {
		return ""
	}
	lower := strings.ToLower(result)
	for _, p := range injectionPhrases {
		if strings.Contains(lower, p) {
			return p
		}
	}
	return ""
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
