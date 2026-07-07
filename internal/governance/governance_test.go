package governance

import (
	"testing"
	"time"

	"github.com/HT88-exe/steiner/internal/config"
)

func TestToolAllowed(t *testing.T) {
	cases := []struct {
		name  string
		p     config.Principal
		tool  string
		allow bool
	}{
		{"no lists allows all", config.Principal{}, "fs_read", true},
		{"allow match", config.Principal{Allow: []string{"fs_*"}}, "fs_read", true},
		{"allow miss", config.Principal{Allow: []string{"fs_*"}}, "web_fetch", false},
		{"deny overrides allow", config.Principal{Allow: []string{"fs_*"}, Deny: []string{"fs_write*"}}, "fs_write_file", false},
		{"deny only", config.Principal{Deny: []string{"*_delete"}}, "fs_delete", false},
		{"deny only, other tool", config.Principal{Deny: []string{"*_delete"}}, "fs_read", true},
	}
	for _, c := range cases {
		if got := ToolAllowed(c.p, c.tool); got != c.allow {
			t.Errorf("%s: ToolAllowed(%q) = %v, want %v", c.name, c.tool, got, c.allow)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	l := NewLimiter()
	l.SetClockForTest(func() time.Time { return now })

	p := config.Principal{Name: "a", RateLimit: &config.RateLimit{PerMinute: 2, PerDay: 3}}

	for i := 0; i < 2; i++ {
		if _, _, ok := l.Allow(p); !ok {
			t.Fatalf("call %d should pass", i+1)
		}
	}
	if code, _, ok := l.Allow(p); ok || code != "denied_rate_minute" {
		t.Fatalf("3rd call in minute: ok=%v code=%s", ok, code)
	}

	now = now.Add(61 * time.Second)
	if _, _, ok := l.Allow(p); !ok {
		t.Fatal("new minute window should pass")
	}
	if code, _, ok := l.Allow(p); ok || code != "denied_rate_day" {
		t.Fatalf("4th call in day: ok=%v code=%s", ok, code)
	}

	now = now.Add(25 * time.Hour)
	if _, _, ok := l.Allow(p); !ok {
		t.Fatal("new day window should pass")
	}

	unlimited := config.Principal{Name: "b"}
	for i := 0; i < 100; i++ {
		if _, _, ok := l.Allow(unlimited); !ok {
			t.Fatal("unlimited principal must never be limited")
		}
	}
}
