// Command steiner is the Steiner MCP security gateway CLI.
// If you are looking for the gateway itself, run `steiner run`.
// Btw if ur wondering why its called steiner is cause of steins;gate lmao get it cause its a gateway and steins;gate is a gateway and steiner is a gateway and its a pun on steins;gate and steiner is a german name and stein means stone in german and stones are hard and gateways are hard to make and i am tired of writing this comment so im just gonna stop now bye
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/HT88-exe/steiner/internal/admin"
	"github.com/HT88-exe/steiner/internal/audit"
	"github.com/HT88-exe/steiner/internal/auth"
	"github.com/HT88-exe/steiner/internal/config"
	"github.com/HT88-exe/steiner/internal/gateway"
	"github.com/HT88-exe/steiner/internal/policytest"
	"github.com/HT88-exe/steiner/internal/upstream"
	"github.com/HT88-exe/steiner/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const usage = `steiner — MCP security gateway

Usage:
  steiner init                      write a starter steiner.yaml
  steiner run [flags]               run the gateway
      --config <path>                 config file (default steiner.yaml)
      --stdio                         serve MCP over stdio instead of HTTP
      --verbose                       debug logging
  steiner keygen --name <principal> issue an API key for a principal
  steiner audit [flags]             query the audit log
      --principal, --decision, --tool, --limit, --json
  steiner approvals list            list pending approvals
  steiner approvals approve <id>    approve a pending call
  steiner approvals deny <id>       deny a pending call
  steiner policy test <file>        run attack-scenario fixtures
  steiner version                   print version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "run":
		err = cmdRun(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "approvals":
		err = cmdApprovals(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "version":
		fmt.Println("steiner", version.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdInit() error {
	const path = "steiner.yaml"
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; not overwriting", path)
	}
	if err := os.WriteFile(path, []byte(config.Starter), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", path)
	fmt.Println("next: steiner keygen --name agent-a && steiner run")
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "steiner.yaml", "config file")
	stdio := fs.Bool("stdio", false, "serve MCP over stdio (for local clients that launch the gateway)")
	verbose := fs.Bool("verbose", false, "debug logging")
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	// Logs always go to stderr: in --stdio mode stdout carries the protocol
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	auditLog, err := audit.Open(cfg.ResolvePath(cfg.AuditDB))
	if err != nil {
		return err
	}
	defer auditLog.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ups := upstream.NewManager(logger)
	if err := ups.Connect(ctx, cfg.Upstreams); err != nil {
		return err
	}
	defer ups.Close()

	gw := gateway.New(cfg, ups, auditLog, logger)

	adminSrv := &admin.Server{Audit: auditLog, Broker: gw.Broker, Key: cfg.AdminKey}

	if *stdio {
		principal, err := gw.PrincipalFor(cfg.DefaultPrincipal)
		if err != nil {
			return err
		}
		// The admin API still runs so approvals and the trace viewer work.
		go func() {
			srv := &http.Server{Addr: cfg.AdminListen, Handler: adminSrv.Handler()}
			logger.Info("admin api listening", "addr", "http://"+cfg.AdminListen)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("admin api failed", "err", err)
			}
		}()
		logger.Info("serving MCP over stdio", "principal", principal.Name)
		return gw.NewServer(principal).Run(ctx, &mcp.StdioTransport{})
	}

	verifier, err := auth.NewVerifier(cfg.ResolvePath(cfg.KeysFile))
	if err != nil {
		return err
	}
	return gw.ServeHTTP(ctx, verifier, adminSrv.Handler())
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	name := fs.String("name", "", "principal name (must exist in config)")
	cfgPath := fs.String("config", "steiner.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, ok := cfg.Principal(*name); !ok {
		return fmt.Errorf("principal %q is not in %s; add it under principals: first", *name, *cfgPath)
	}
	token, err := auth.Generate(cfg.ResolvePath(cfg.KeysFile), *name)
	if err != nil {
		return err
	}
	fmt.Printf("API key for %q (shown once, store it now):\n\n  %s\n\n", *name, token)
	fmt.Printf("connect clients to http://%s/mcp with header:\n  Authorization: Bearer %s\n", cfg.Listen, token)
	return nil
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	cfgPath := fs.String("config", "steiner.yaml", "config file")
	principal := fs.String("principal", "", "filter by principal")
	decision := fs.String("decision", "", "filter by decision code")
	tool := fs.String("tool", "", "filter by tool")
	limit := fs.Int("limit", 50, "max events")
	asJSON := fs.Bool("json", false, "emit JSONL (SIEM-friendly)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	log, err := audit.Open(cfg.ResolvePath(cfg.AuditDB))
	if err != nil {
		return err
	}
	defer log.Close()

	events, err := log.Events(audit.Query{
		Principal: *principal, Decision: *decision, Tool: *tool, Limit: *limit,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range events {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	}
	if len(events) == 0 {
		fmt.Println("no events")
		return nil
	}
	for _, e := range events {
		taint := ""
		if e.Tainted {
			taint = " [tainted]"
		}
		detail := e.Reason
		if detail == "" {
			detail = e.Args
		}
		fmt.Printf("%s  %-18s %-10s %-28s %-22s %s%s\n",
			e.Time.Format(time.RFC3339), e.SessionKey, e.Principal,
			firstN(e.Tool, 28), e.Decision, firstN(detail, 80), taint)
	}
	return nil
}

func cmdApprovals(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: steiner approvals list|approve <id>|deny <id>")
	}
	fs := flag.NewFlagSet("approvals", flag.ExitOnError)
	cfgPath := fs.String("config", "steiner.yaml", "config file")
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rest := fs.Args()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	base := "http://" + cfg.AdminListen

	switch sub {
	case "list":
		var pending []map[string]any
		if err := adminGet(cfg, base+"/api/approvals", &pending); err != nil {
			return err
		}
		if len(pending) == 0 {
			fmt.Println("no pending approvals")
			return nil
		}
		for _, a := range pending {
			fmt.Printf("%s  principal=%s tool=%s\n  args: %s\n",
				a["id"], a["principal"], a["tool"], a["args"])
		}
		return nil
	case "approve", "deny":
		if len(rest) != 1 {
			return fmt.Errorf("usage: steiner approvals %s <id>", sub)
		}
		body, _ := json.Marshal(map[string]bool{"approve": sub == "approve"})
		req, err := http.NewRequest(http.MethodPost, base+"/api/approvals/"+rest[0], bytes.NewReader(body))
		if err != nil {
			return err
		}
		return adminDo(cfg, req, nil)
	default:
		return fmt.Errorf("unknown approvals subcommand %q", sub)
	}
}

func cmdPolicy(args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return fmt.Errorf("usage: steiner policy test <scenarios.yaml>")
	}
	fs := flag.NewFlagSet("policy test", flag.ExitOnError)
	cfgPath := fs.String("config", "steiner.yaml", "config file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: steiner policy test <scenarios.yaml>")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	return policytest.Run(cfg, fs.Arg(0), os.Stdout)
}

func adminGet(cfg *config.Config, url string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return adminDo(cfg, req, out)
}

func adminDo(cfg *config.Config, req *http.Request, out any) error {
	if cfg.AdminKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.AdminKey)
	}
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("is the gateway running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin api: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	fmt.Println("ok")
	return nil
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
