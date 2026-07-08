# Reproducing the containment demo

Walkthrough for the flagship demo: an injected web page attempts exfiltration,
and Steiner blocks the outbound call.

## Offline eval (fastest)

No running gateway required:

```bash
steiner policy test examples/attacks/scenarios.yaml
```

Scenario 01 is the trifecta block. Expect `10/10 scenarios passed`.

## Live demo with an agent

1. Prepare a directory:

   ```bash
   mkdir demo && cd demo
   echo "SECRET=example-value" > .env
   steiner init
   steiner keygen --name agent-a
   ```

2. In `steiner.yaml`, ensure `agent-a` can read files and that the starter
   policy lists web tools as untrusted sources and `*_send` as external sinks.

3. Start the gateway:

   ```bash
   steiner run
   ```

   Open the trace viewer at http://127.0.0.1:8386/

4. Connect your agent to `http://127.0.0.1:8385/mcp` with the bearer key.
   Ask it to summarize a page whose content includes an instruction to read
   `.env` and email it to an external address.

5. Observe: the read succeeds (session becomes tainted); the send is denied
   with `denied_tainted_sink` in the trace viewer.

## Key points

- The block is **deterministic** — it does not depend on recognizing injection
  text.
- Read-only tools continue to work after taint.
- `steiner audit` records the full sequence with secrets redacted.
