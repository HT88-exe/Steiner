# Contributing to Steiner

Thanks for your interest. Steiner is an open-core project: the gateway, policy
engine, and CLI in this repo are Apache-2.0 and will stay that way.

## Development

Requires Go 1.26+.

```bash
go build ./...
go test ./...            # unit + in-memory end-to-end tests
go test ./... -run TestRealFilesystemServer   # needs npx + network
gofmt -l .               # must be empty
go vet ./...
```

CI runs build, vet, `gofmt`, and the race detector on Linux and Windows.

## Layout

| Package | Responsibility |
| --- | --- |
| `cmd/steiner` | CLI entrypoint. |
| `internal/config` | Config loading, defaults, validation. |
| `internal/auth` | API-key issue/verify + HTTP auth middleware. |
| `internal/upstream` | Upstream connections and feature sync. |
| `internal/gateway` | Virtual server, enforcement pipeline, HTTP ingress. |
| `internal/governance` | Allow/deny lists and rate limits. |
| `internal/policy` | Containment engine, approvals broker. |
| `internal/detect` | Heuristic detectors. |
| `internal/dlp` | Secret/PII patterns + redaction. |
| `internal/audit` | Append-only SQLite log. |
| `internal/admin` | Loopback admin API + trace viewer. |
| `internal/policytest` | Attack-scenario fixture runner. |

## Guidelines

- **Containment is the product.** Changes that weaken the trifecta guarantee,
  or that make a denial silent, need a strong justification.
- **Deny loudly, in-band.** Blocked calls return a tool error the model can
  read, and always produce an audit row.
- **Never persist secrets.** Anything written to the audit log goes through
  `dlp.Redact` first. Keep it that way.
- Add a scenario to `examples/attacks/scenarios.yaml` when you add or change a
  policy behavior.
