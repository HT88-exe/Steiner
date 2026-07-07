package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Log {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestRecordAndQuery(t *testing.T) {
	l := openTemp(t)

	events := []*Event{
		{Principal: "a", Tool: "fs_read", Method: "tools/call", Decision: "allowed", LatencyMS: 4},
		{Principal: "a", Tool: "mail_send", Method: "tools/call", Decision: "denied_tainted_sink", Reason: "tainted", Tainted: true},
		{Principal: "b", Tool: "fs_read", Method: "tools/call", Decision: "allowed", Flags: []string{"arg_rule:x"}},
	}
	for _, e := range events {
		if err := l.Record(e); err != nil {
			t.Fatal(err)
		}
	}

	all, err := l.Events(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d events, want 3", len(all))
	}
	if all[0].Tool != "fs_read" || all[0].Principal != "b" {
		t.Fatalf("events must be newest-first, got %+v", all[0])
	}
	if len(all[0].Flags) != 1 || all[0].Flags[0] != "arg_rule:x" {
		t.Fatalf("flags roundtrip failed: %+v", all[0].Flags)
	}

	denied, err := l.Events(Query{Decision: "denied_tainted_sink"})
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 1 || !denied[0].Tainted || denied[0].Reason != "tainted" {
		t.Fatalf("decision filter failed: %+v", denied)
	}

	byPrincipal, err := l.Events(Query{Principal: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byPrincipal) != 2 {
		t.Fatalf("principal filter: got %d, want 2", len(byPrincipal))
	}

	limited, err := l.Events(Query{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 1 {
		t.Fatalf("limit ignored: got %d", len(limited))
	}
}

func TestArgsAreRedacted(t *testing.T) {
	l := openTemp(t)
	err := l.Record(&Event{
		Principal: "a", Tool: "t", Decision: "allowed",
		Args: `{"token":"AKIAIOSFODNN7EXAMPLE"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.Events(Query{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got[0].Args, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("secret persisted unredacted in audit log")
	}
	if !strings.Contains(got[0].Args, "[REDACTED:aws-access-key]") {
		t.Fatalf("redaction marker missing: %s", got[0].Args)
	}
}

func TestSinceFilter(t *testing.T) {
	l := openTemp(t)
	old := &Event{Principal: "a", Tool: "t", Decision: "allowed", Time: time.Now().Add(-2 * time.Hour).UTC()}
	recent := &Event{Principal: "a", Tool: "t2", Decision: "allowed"}
	if err := l.Record(old); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(recent); err != nil {
		t.Fatal(err)
	}
	got, err := l.Events(Query{Since: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tool != "t2" {
		t.Fatalf("since filter failed: %+v", got)
	}
}
