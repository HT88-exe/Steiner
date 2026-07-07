# MCP specification compatibility

Steiner builds on the official MCP Go SDK
(`github.com/modelcontextprotocol/go-sdk`).

## Current target

- **SDK:** v1.6.1 (stable)
- **Protocol:** 2025-11-25 and earlier, negotiated per client. The SDK
  auto-negotiates down for older clients, so Cursor and Claude Desktop work
  today with no configuration.

## The 2026-07-28 revision

The 2026-07-28 MCP revision (final spec published July 28, 2026; SDK support
in v1.7.0) is the largest change since launch, and two parts of it are
directly relevant to a gateway:

1. **Stateless Streamable HTTP.** The `initialize` handshake and the
   `Mcp-Session-Id` header are removed; every request is self-contained, so
   remote servers no longer need sticky sessions and scale horizontally.
2. **Routing headers (SEP-2243).** POST requests must carry `Mcp-Method` and
   `Mcp-Name` headers mirroring the JSON-RPC body, precisely so gateways, load
   balancers, and rate-limiters can route and police traffic **without deep
   packet inspection**. Servers reject requests where the headers and body
   disagree.

SEP-2243 is a gateway feature. It exists so software like Steiner can make
decisions from headers alone.

## How Steiner is already aligned

- **Session identity is ours, not the protocol's.** Steiner mints its own
  session key and uses it both as the HTTP `Mcp-Session-Id` (while that still
  exists) and as the audit correlation key. Taint state and session-ownership
  checks hang off this key, never off protocol session state. When the
  protocol drops sessions, our taint model is unaffected.
- **We already validate SEP-2243 headers.** `mcpHeadersMiddleware` in
  [internal/gateway/serve.go](../internal/gateway/serve.go) cross-checks
  `Mcp-Method` / `Mcp-Name` against the body when a client sends them, and
  rejects mismatches with `400`. Clients on older revisions omit the headers
  and are passed through untouched.

## The upgrade path to v1.7.0

When adopting the v1.7.0 SDK:

1. `go get github.com/modelcontextprotocol/go-sdk@v1.7.0`.
2. Set `StreamableHTTPOptions.Stateless = true` on the ingress handler to
   serve `2026-07-28`. Leaving it unset keeps clients negotiating down to
   `2025-11-25`, so this is a safe, opt-in switch.
3. Make the SEP-2243 header cross-check mandatory (not just best-effort) on
   the stateless path, and route/rate-limit directly from the headers.
4. Move taint and rate-limit state to a shared store (e.g. Redis) so that
   multiple stateless instances behind a load balancer share one view. The
   in-memory maps used today are structured behind interfaces to make this a
   contained change.

Because session identity and header validation are already independent of the
protocol's session mechanism, "day-one 2026-07-28 support" is a small, planned
step rather than a rewrite.
