// Package dlp holds the built-in data-loss-prevention patterns used both to
// block secrets in outbound tool arguments and to redact audit records.
package dlp

import "regexp"

// Rule is a named secret/PII pattern.
type Rule struct {
	ID string
	RE *regexp.Regexp
}

// Builtin patterns favor precision over recall: each match is near-certainly
// sensitive, so they are safe to enforce with "block".
var Builtin = []Rule{
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"api-secret-key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`)},
	{"private-key-block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`)},
	{"us-ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"payment-card", regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)(?:[ -]?\d{4}){3}\b`)},
}

// Scan returns the IDs of built-in rules matching s.
func Scan(s string) []string {
	var ids []string
	for _, r := range Builtin {
		if r.RE.MatchString(s) {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// Redact masks every built-in pattern match in s. Audit records pass through
// here so secrets never land in the audit database.
func Redact(s string) string {
	for _, r := range Builtin {
		s = r.RE.ReplaceAllString(s, "[REDACTED:"+r.ID+"]")
	}
	return s
}
