package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Approval is a pending human-in-the-loop decision.
type Approval struct {
	ID        string    `json:"id"`
	Principal string    `json:"principal"`
	Tool      string    `json:"tool"`
	Args      string    `json:"args"`
	Reason    string    `json:"reason"`
	Created   time.Time `json:"created"`

	decided chan bool `json:"-"`
	once    sync.Once `json:"-"`
}

// Broker queues approvals and resolves them from the admin API (or an MCP
// elicitation, handled by the gateway before falling back to the broker).
type Broker struct {
	mu      sync.Mutex
	pending map[string]*Approval
	slack   string
}

// NewBroker returns a Broker. slackWebhook may be empty.
func NewBroker(slackWebhook string) *Broker {
	return &Broker{pending: map[string]*Approval{}, slack: slackWebhook}
}

// Request enqueues an approval and blocks until it is decided, the timeout
// elapses, or ctx is canceled. It returns true only on explicit approval.
func (b *Broker) Request(ctx context.Context, principal, tool, args, reason string, timeout time.Duration) (bool, string) {
	a := &Approval{
		ID:        uuid.NewString(),
		Principal: principal,
		Tool:      tool,
		Args:      truncate(args, 2000),
		Reason:    reason,
		Created:   time.Now().UTC(),
		decided:   make(chan bool, 1),
	}
	b.mu.Lock()
	b.pending[a.ID] = a
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, a.ID)
		b.mu.Unlock()
	}()

	b.notifySlack(a)

	select {
	case ok := <-a.decided:
		if ok {
			return true, "approved by operator"
		}
		return false, "denied by operator"
	case <-time.After(timeout):
		return false, fmt.Sprintf("approval timed out after %s", timeout)
	case <-ctx.Done():
		return false, "call canceled while awaiting approval"
	}
}

// Pending lists undecided approvals, oldest first.
func (b *Broker) Pending() []*Approval {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Approval, 0, len(b.pending))
	for _, a := range b.pending {
		out = append(out, a)
	}
	// Small n; simple selection order by creation time.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Created.Before(out[i].Created) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Decide resolves a pending approval by ID.
func (b *Broker) Decide(id string, approve bool) error {
	b.mu.Lock()
	a := b.pending[id]
	b.mu.Unlock()
	if a == nil {
		return fmt.Errorf("no pending approval %q", id)
	}
	a.once.Do(func() { a.decided <- approve })
	return nil
}

// notifySlack posts fire-and-forget; approval flow works without Slack.
func (b *Broker) notifySlack(a *Approval) {
	if b.slack == "" {
		return
	}
	payload, err := json.Marshal(map[string]string{
		"text": fmt.Sprintf("Steiner approval needed: principal %q wants to call %s\nargs: %s\napprove with: steiner approvals approve %s",
			a.Principal, a.Tool, a.Args, a.ID),
	})
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.slack, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
