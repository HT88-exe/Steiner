# Contributing to Steiner

Thank you for contributing. Steiner is open source under Apache 2.0.

## Before you start

- Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities.
- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in all project spaces.

## Development

Requires Go 1.26+.

```bash
git clone https://github.com/HT88-exe/steiner.git
cd steiner
go build ./...
go test ./...
go vet ./...
gofmt -l .    # must print nothing
```

Optional integration test (requires `npx` and network):

```bash
go test ./internal/upstream/ -run TestRealFilesystemServer
```

CI runs build, vet, `gofmt`, and tests on Linux and Windows.

## Project layout

| Package | Responsibility |
| --- | --- |
| `cmd/steiner` | CLI entrypoint |
| `internal/config` | Configuration loading and validation |
| `internal/auth` | API keys and HTTP authentication |
| `internal/upstream` | Upstream MCP connections |
| `internal/gateway` | Virtual server and enforcement pipeline |
| `internal/governance` | Allowlists and rate limits |
| `internal/policy` | Containment engine and approvals |
| `internal/detect` | Heuristic detectors |
| `internal/dlp` | Secret patterns and redaction |
| `internal/audit` | Append-only audit log |
| `internal/admin` | Admin API and trace viewer |
| `internal/policytest` | Scenario fixture runner |

## Guidelines

- **Containment is the product.** Do not weaken the trifecta guarantee without
  strong justification.
- **Deny in-band.** Blocked calls must return a readable tool error and write an
  audit row.
- **Never persist secrets.** Audit arguments pass through `dlp.Redact`.
- **Add scenarios.** Policy changes should include a fixture in
  `examples/attacks/scenarios.yaml`.

## Pull requests

1. Fork and branch from `master`.
2. Keep changes focused; match existing style.
3. Run `go test ./...` before opening the PR.
4. Describe the security impact if the change touches auth, policy, or audit.
