package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "steiner.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStarterConfigLoads(t *testing.T) {
	cfg, err := Load(write(t, Starter))
	if err != nil {
		t.Fatalf("starter config must load: %v", err)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "fs" {
		t.Fatalf("unexpected upstreams: %+v", cfg.Upstreams)
	}
	if cfg.Policy == nil || cfg.Policy.BlockSinksWhenTainted == nil || !*cfg.Policy.BlockSinksWhenTainted {
		t.Fatal("starter policy should enable the trifecta rule")
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(write(t, "upstreams: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8385" || cfg.AdminListen != "127.0.0.1:8386" {
		t.Fatalf("bad listen defaults: %s %s", cfg.Listen, cfg.AdminListen)
	}
	if cfg.DefaultPrincipal != "local" {
		t.Fatalf("default principal = %q", cfg.DefaultPrincipal)
	}
	if _, ok := cfg.Principal("local"); !ok {
		t.Fatal("implicit local principal missing")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"bad transport":   "upstreams:\n  - name: a\n    transport: tcp\n",
		"missing command": "upstreams:\n  - name: a\n    transport: stdio\n",
		"missing url":     "upstreams:\n  - name: a\n    transport: http\n",
		"bad name":        "upstreams:\n  - name: BadName\n    transport: stdio\n    command: x\n",
		"duplicate name":  "upstreams:\n  - {name: a, transport: stdio, command: x}\n  - {name: a, transport: stdio, command: y}\n",
		"unknown field":   "upstreams: []\nnot_a_real_key: 1\n",
		"bad arg action":  "policy:\n  arg_rules:\n    - {id: r, pattern: x, action: explode}\n",
		"bad arg pattern": "policy:\n  arg_rules:\n    - {id: r, pattern: '[', action: block}\n",
		"bad allow glob":  "principals:\n  - name: p\n    allow: ['[']\n",
	}
	for name, content := range cases {
		if _, err := Load(write(t, content)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestResolvePath(t *testing.T) {
	path := write(t, "upstreams: []\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.ResolvePath("audit.db")
	if !strings.HasPrefix(got, filepath.Dir(path)) {
		t.Fatalf("relative path not anchored to config dir: %s", got)
	}
	abs := filepath.Join(t.TempDir(), "x.db")
	if cfg.ResolvePath(abs) != abs {
		t.Fatal("absolute paths must pass through")
	}
}
