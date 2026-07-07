package upstream_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HT88-exe/steiner/internal/audit"
	"github.com/HT88-exe/steiner/internal/config"
	"github.com/HT88-exe/steiner/internal/gateway"
	"github.com/HT88-exe/steiner/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRealFilesystemServer proxies a real @modelcontextprotocol/server-filesystem
// process through the full gateway pipeline. It needs npx and network access
// for the first package download, so it is skipped in short mode and when
// npx is unavailable.
func TestRealFilesystemServer(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "hello.txt"), "steiner e2e"); err != nil {
		t.Fatal(err)
	}

	cfgYAML := `
upstreams:
  - name: fs
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "` + filepath.ToSlash(dir) + `"]
principals:
  - name: local
    deny: ["fs_write_file", "fs_edit_file", "fs_move_file"]
`
	cfgPath := filepath.Join(dir, "steiner.yaml")
	if err := writeFile(cfgPath, cfgYAML); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuditDB = filepath.Join(dir, "audit.db")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditLog, err := audit.Open(cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()

	ups := upstream.NewManager(logger)
	if err := ups.Connect(ctx, cfg.Upstreams); err != nil {
		t.Skipf("could not start filesystem server (offline?): %v", err)
	}
	defer ups.Close()

	gw := gateway.New(cfg, ups, auditLog, logger)
	principal, err := gw.PrincipalFor("local")
	if err != nil {
		t.Fatal(err)
	}
	srv := gw.NewServer(principal)

	st, ct := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Tools are namespaced, and denied ones are absent.
	var names []string
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	if len(names) == 0 {
		t.Fatal("no tools aggregated from filesystem server")
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "fs_") {
			t.Fatalf("tool %q not namespaced", n)
		}
		if n == "fs_write_file" {
			t.Fatal("denied tool exposed")
		}
	}

	// A real read through the whole pipeline.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "fs_read_text_file",
		Arguments: map[string]any{"path": filepath.Join(dir, "hello.txt")},
	})
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	if res.IsError || !strings.Contains(text.String(), "steiner e2e") {
		t.Fatalf("read through gateway failed: isError=%v %q", res.IsError, text.String())
	}

	// And it was audited.
	events, err := auditLog.Events(audit.Query{Tool: "fs_read_text_file"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Decision != "allowed" {
		t.Fatalf("audit trail missing: %+v", events)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
