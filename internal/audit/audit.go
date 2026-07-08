// Package audit implements Steiner's append-only audit log.
// Every decision the gateway makes; allowed or denied, tool call, resource read, or prompt get, is recorded as one row.
// The log is written by the gateway and read by `steiner audit` and the admin trace viewer.
// There is no update or delete path.
package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/HT88-exe/steiner/internal/dlp"
	_ "modernc.org/sqlite"
)

// Event is one audit record.
type Event struct {
	ID           int64     `json:"id"`
	Time         time.Time `json:"time"`
	SessionKey   string    `json:"session_key"`
	Principal    string    `json:"principal"`
	Upstream     string    `json:"upstream"`
	Tool         string    `json:"tool"`
	Method       string    `json:"method"`
	Args         string    `json:"args,omitempty"`
	ResultDigest string    `json:"result_digest,omitempty"`
	ResultLen    int       `json:"result_len"`
	Decision     string    `json:"decision"`
	Reason       string    `json:"reason,omitempty"`
	Flags        []string  `json:"flags,omitempty"`
	LatencyMS    int64     `json:"latency_ms"`
	Tainted      bool      `json:"tainted"`
}

// Log is a handle to the audit database.
type Log struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	session_key TEXT NOT NULL DEFAULT '',
	principal TEXT NOT NULL DEFAULT '',
	upstream TEXT NOT NULL DEFAULT '',
	tool TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT '',
	args TEXT NOT NULL DEFAULT '',
	result_digest TEXT NOT NULL DEFAULT '',
	result_len INTEGER NOT NULL DEFAULT 0,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	flags TEXT NOT NULL DEFAULT '[]',
	latency_ms INTEGER NOT NULL DEFAULT 0,
	tainted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_principal ON events(principal);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
`

// Open opens (creating if needed) the audit database at path.
func Open(path string) (*Log, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc.org/sqlite serializes writes; a single writer connection avoids
	// SQLITE_BUSY between the gateway and admin reads.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing audit schema: %w", err)
	}
	return &Log{db: db}, nil
}

// Close closes the database.
func (l *Log) Close() error { return l.db.Close() }

// Record appends one event.
// Args are redacted before storage so secrets never persist in the audit trail.
func (l *Log) Record(e *Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	flags, err := json.Marshal(e.Flags)
	if err != nil {
		flags = []byte("[]")
	}
	_, err = l.db.Exec(`INSERT INTO events
		(ts, session_key, principal, upstream, tool, method, args, result_digest, result_len, decision, reason, flags, latency_ms, tainted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Time.Format(time.RFC3339Nano), e.SessionKey, e.Principal, e.Upstream, e.Tool, e.Method,
		dlp.Redact(e.Args), e.ResultDigest, e.ResultLen, e.Decision, e.Reason, string(flags), e.LatencyMS, boolToInt(e.Tainted))
	return err
}

// Digest returns the audit digest of a result payload.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// Query filters audit events. Zero values mean "no filter".
type Query struct {
	Principal string
	Decision  string
	Tool      string
	Since     time.Time
	Limit     int
}

// Events returns matching events, newest first.
func (l *Log) Events(q Query) ([]Event, error) {
	var (
		where []string
		args  []any
	)
	if q.Principal != "" {
		where = append(where, "principal = ?")
		args = append(args, q.Principal)
	}
	if q.Decision != "" {
		where = append(where, "decision = ?")
		args = append(args, q.Decision)
	}
	if q.Tool != "" {
		where = append(where, "tool = ?")
		args = append(args, q.Tool)
	}
	if !q.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, q.Since.UTC().Format(time.RFC3339Nano))
	}
	sqlq := "SELECT id, ts, session_key, principal, upstream, tool, method, args, result_digest, result_len, decision, reason, flags, latency_ms, tainted FROM events"
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ")
	}
	sqlq += " ORDER BY id DESC"
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	sqlq += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := l.db.Query(sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var (
			e       Event
			ts      string
			flags   string
			tainted int
		)
		if err := rows.Scan(&e.ID, &ts, &e.SessionKey, &e.Principal, &e.Upstream, &e.Tool, &e.Method,
			&e.Args, &e.ResultDigest, &e.ResultLen, &e.Decision, &e.Reason, &flags, &e.LatencyMS, &tainted); err != nil {
			return nil, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, ts)
		_ = json.Unmarshal([]byte(flags), &e.Flags)
		e.Tainted = tainted != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
