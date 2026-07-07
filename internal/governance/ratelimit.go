// Package governance implements per-principal rate limits and budgets.
package governance

import (
	"fmt"
	"sync"
	"time"

	"github.com/brueing/steiner/internal/config"
)

// Limiter enforces fixed-window per-minute and per-day limits. Fixed windows
// keep audit messages predictable ("61st call this minute").
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
	now     func() time.Time
}

type window struct {
	minuteStart time.Time
	minuteCount int
	dayStart    time.Time
	dayCount    int
}

// NewLimiter returns a Limiter using the real clock.
func NewLimiter() *Limiter {
	return &Limiter{windows: map[string]*window{}, now: time.Now}
}

// SetClockForTest overrides the clock.
func (l *Limiter) SetClockForTest(now func() time.Time) { l.now = now }

// Allow records one call for the principal and reports whether it is within
// its limits. When denied, code and reason describe the exhausted window.
func (l *Limiter) Allow(p config.Principal) (code, reason string, ok bool) {
	if p.RateLimit == nil {
		return "", "", true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	w := l.windows[p.Name]
	if w == nil {
		w = &window{}
		l.windows[p.Name] = w
	}
	if now.Sub(w.minuteStart) >= time.Minute {
		w.minuteStart, w.minuteCount = now, 0
	}
	if now.Sub(w.dayStart) >= 24*time.Hour {
		w.dayStart, w.dayCount = now, 0
	}
	if p.RateLimit.PerMinute > 0 && w.minuteCount >= p.RateLimit.PerMinute {
		return "denied_rate_minute",
			fmt.Sprintf("per-minute limit reached (%d/min)", p.RateLimit.PerMinute), false
	}
	if p.RateLimit.PerDay > 0 && w.dayCount >= p.RateLimit.PerDay {
		return "denied_rate_day",
			fmt.Sprintf("daily budget reached (%d/day)", p.RateLimit.PerDay), false
	}
	w.minuteCount++
	w.dayCount++
	return "", "", true
}
