# Release checklist

Steps for publishing Steiner on GitHub and announcing v0.1.0.

## Pre-release

- [ ] `go test ./...` passes locally
- [ ] `steiner policy test examples/attacks/scenarios.yaml` → 10/10
- [ ] `gofmt -l .` is empty
- [ ] README quickstart verified on a clean machine
- [ ] No secrets in the repo (`steiner.keys.yaml`, `*.db`)

## GitHub

- [ ] Push to https://github.com/HT88-exe/steiner
- [ ] CI green on Actions tab
- [ ] Set repository **About**: description, topics (`mcp`, `security`, `golang`,
      `ai-agents`, `prompt-injection`)
- [ ] Enable **Issues** and **Private vulnerability reporting**
- [ ] Tag `v0.1.0` and publish a GitHub Release (copy from CHANGELOG.md)

## Demo (recommended before announcement)

1. `steiner init` — show policy: web tools are untrusted, mail is a sink.
2. `steiner run` — open trace viewer at `:8386`.
3. Connect an agent; ask it to read a page with a hidden exfiltration instruction.
4. Show `denied_tainted_sink` in the trace viewer when it tries to send mail.
5. `steiner audit` — full trail, secrets redacted.

## Announcement copy (Show HN)

> **Show HN: Steiner – MCP security gateway (assume injection, contain it)**
>
> Steiner is a proxy between AI agents and MCP tool servers. Instead of trying
> to detect every prompt injection, it enforces deterministic containment: when
> a session reads untrusted content, it is tainted and blocked from tools that
> can send data out.
>
> Go, one binary, Apache-2.0. Runnable eval:
> `steiner policy test examples/attacks/scenarios.yaml`
>
> https://github.com/HT88-exe/steiner

## Follow-up posts

1. **Security:** taint tracking and the lethal trifecta for agent sessions.
2. **Engineering:** building an MCP gateway in Go (aggregation, session
   identity, testing with in-memory transports).

## Channels

Hacker News, r/mcp, r/LocalLLaMA, MCP Discord, lobste.rs.
