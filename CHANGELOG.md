# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-07-08

### Added

- `steiner trace` command to serve the trace viewer from the audit database on disk.

### Fixed

- Trace viewer no longer shows an empty table when the admin API fails; errors are displayed in the UI.
- Admin API reads the audit log through a separate read-only SQLite connection so the viewer stays in sync while the gateway is running.

[0.1.1]: https://github.com/HT88-exe/steiner/releases/tag/v0.1.1

## [0.1.0] - 2026-07-08

### Added

- MCP security gateway: transparent proxy over stdio and Streamable HTTP upstreams.
- Tool aggregation with `<upstream>_<tool>` namespacing and `list_changed` propagation.
- Per-principal API keys, allow/deny lists, and rate limits.
- Session taint tracking and the lethal-trifecta containment rule.
- Built-in DLP on outbound tool arguments and configurable argument rules.
- Human-in-the-loop approvals via MCP elicitation and an admin approval queue.
- Heuristic detectors for high-entropy payloads, novel domains, and injection phrasing.
- Append-only SQLite audit log with secret redaction.
- `steiner audit` CLI with JSONL export.
- Loopback admin API and live trace viewer.
- `steiner policy test` fixture runner.
- Ten-scenario containment eval in `examples/attacks/scenarios.yaml`.
- Cross-platform CI (Linux and Windows).

[0.1.0]: https://github.com/HT88-exe/steiner/releases/tag/v0.1.0
