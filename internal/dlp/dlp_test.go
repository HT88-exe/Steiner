package dlp

import (
	"strings"
	"testing"
)

func TestScan(t *testing.T) {
	cases := []struct {
		in   string
		want string // expected rule id, "" for no match
	}{
		{`{"key":"AKIAIOSFODNN7EXAMPLE"}`, "aws-access-key"},
		{`token ghp_abcdefghijklmnopqrst1234`, "github-token"},
		{`-----BEGIN RSA PRIVATE KEY-----`, "private-key-block"},
		{`ssn is 123-45-6789`, "us-ssn"},
		{`card 4111-1111-1111-1111`, "payment-card"},
		{`{"url":"https://example.com","q":"weather"}`, ""},
		{`build 123-45 finished`, ""},
	}
	for _, c := range cases {
		ids := Scan(c.in)
		if c.want == "" {
			if len(ids) != 0 {
				t.Errorf("Scan(%q) = %v, want none", c.in, ids)
			}
			continue
		}
		found := false
		for _, id := range ids {
			if id == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("Scan(%q) = %v, want %s", c.in, ids, c.want)
		}
	}
}

func TestRedact(t *testing.T) {
	in := `creds AKIAIOSFODNN7EXAMPLE and ssn 123-45-6789`
	out := Redact(in)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(out, "123-45-6789") {
		t.Fatalf("secrets survived redaction: %s", out)
	}
	if !strings.Contains(out, "[REDACTED:aws-access-key]") || !strings.Contains(out, "[REDACTED:us-ssn]") {
		t.Fatalf("redaction markers missing: %s", out)
	}
}
