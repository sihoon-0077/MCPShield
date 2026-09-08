# MCPShield Gateway

The Gateway accepts an artifact directory, never a caller-provided release ID, digest, tool hash, executable, or arguments. It copies regular files into a private temporary snapshot, computes the scanner-compatible artifact and tool-surface hashes from those exact bytes, validates the `.mjs` manifest entrypoint, checks admission, and starts only that snapshotted entrypoint with the current Node executable.

The child receives only a minimal system environment. Pass an MCP-specific variable intentionally by listing its exact name in `MCPSHIELD_CHILD_ENV_ALLOWLIST`; unrelated parent secrets are not inherited. Runtime injection variables such as `NODE_OPTIONS`, `NODE_PATH`, `LD_*`, and `DYLD_*` are always removed. Artifact code is ESM-only: `.js`, CommonJS, dynamic, absolute, package, native, and WebAssembly module loads are rejected. Loader-shaped raw source is rejected fail-closed so regex or template syntax cannot hide a dynamic import. `.mjs` code may use only an allowlist of non-network `node:` built-ins and relative `.mjs` modules captured inside its snapshot. Node's permission model prevents reads outside that snapshot, string code generation is disabled, child output is capped, and runtime network egress is not supported by this MVP.

```powershell
npm.cmd run test:gateway
npm.cmd run demo:mcp-e2e
```

The `demo:mcp-e2e` command connects the official MCP client through the Gateway. For direct MCP stdio mode set `MCPSHIELD_ARTIFACT_DIR`, `MCPSHIELD_MODE`, `MCPSHIELD_API_URL`, and optionally `MCPSHIELD_ADMISSION_TIMEOUT_MS` or `MCPSHIELD_REPLAY_FILE`, then start `node apps/gateway/src/index.mjs stdio` from an MCP client. The Gateway relays newline-delimited JSON-RPC bytes while observing request IDs. It fully checks JSON-RPC batches, allows only manifest-declared `tools/call` names, and suppresses errored, duplicate, or mismatched `tools/list` responses before terminating the child fail-closed.

`node apps/gateway/src/index.mjs serve` exposes `POST /mcp` over Streamable HTTP for ChatGPT and other remote MCP clients. Its read-only `list_messages` handler runs the same snapshotted stdio artifact through `runArtifact`, so `VERIFIED` is required and `REVOKED` is blocked before spawn. Set `MCPSHIELD_ARTIFACT_DIR` plus the same admission mode variables used by stdio.

Symlinks, traversal entrypoints, non-JavaScript entrypoints, oversized artifacts, arbitrary commands, command arguments, shells, `npx`, and caller-supplied identity values are not accepted. Stop the Gateway service to disable spawning. REPLAY is demo-only and verifies its saved artifact identity; MOCK is display-only and always returns BLOCK in the Gateway.

## Master /v1 admission and active sessions

Every `tools/call` rechecks admission before forwarding its frame. Revocation therefore stops the next call in already-connected stdio clients; malformed replies and unavailable strict admission terminate the child. Requests within a JSON-RPC batch are inspected in order before the complete batch is forwarded.

Set `MCPSHIELD_POLICY_HASH` to enable `/v1/admission/check`. Also configure `MCPSHIELD_CONTROL_RELEASE_ID` (the exact ID returned by `/v1/releases/resolve`), `MCPSHIELD_TENANT_ID`, `MCPSHIELD_CACHE_PUBLIC_KEY` (Ed25519 SPKI PEM), `MCPSHIELD_CACHE_KEY_ID`, `MCPSHIELD_CHAIN_ID`, `MCPSHIELD_REGISTRY_CONTRACT`, `MCPSHIELD_VALIDATOR_SET_VERSION`, and the tenant credential `MCPSHIELD_CONTROL_TOKEN`. These values are administrator-pinned trust context, never read from an untrusted response. The backend signs only complete chain-confirmed evidence; a local-demo or unsigned response cannot authorize this mode. Omitting the policy hash retains the existing legacy `/api` demo contract, which does not provide v1 policy/expiry assurance.

`MCPSHIELD_ADMISSION_MODE=strict` is the default and always requires a fresh API response. `balanced` may reuse a signed snapshot for at most its remaining 60-second validity, and only when the API is unreachable/5xx and the pinned manifest declares all applicable tools read-only and non-destructive. Writes, payments, invalid proof, explicit deny, 4xx, mismatched digest/policy/validator set, and expired snapshots fail closed. A malformed or denied fresh response invalidates the earlier allow cache. Signed status is checked independently of unsigned display fields.

`MCPSHIELD_ADMISSION_CACHE_FILE` optionally persists one wrapper's signed snapshot with restricted file permissions. Without it, a bounded in-process cache is used. Cache availability does not claim zero-delay revocation during a network partition: balanced read-only exposure is bounded by the signed expiry. Strict mode avoids that availability tradeoff. Node's permission boundary and output/import controls remain active in both modes.

The signature proves which configured admission signer issued a decision, not independent blockchain execution. The backend must validate chain freshness and confirmations before signing; the Gateway validates the signed block context, exact local identity, policy, lifetime, and signer key. Test these controls with `npm run test:gateway`.

The signed payload also binds tenant identity and operation class. Cache records include a one-way credential fingerprint, never the credential itself. A snapshot for public reads cannot be reused for private reads, writes, or a different account. Fresh responses are size-limited to 64 KiB, and the admission deadline covers both headers and body. `notifications/tools/list_changed` suspends tool calls until the client refreshes `tools/list` and the exact approved surface matches again.

For staged rollout, `node apps/gateway/src/index.mjs inspect --artifact <directory> --rollout observe|warn|enforce` reports `RECORD_ONLY`, `REVIEW_REQUIRED`, or the enforcement decision without starting any process. `run` and `stdio` always enforce admission; assessment is not a bypass switch or a human-approval implementation. Inspection supports the same `--mode replay --replay <file>` switches for reproducible dry-runs.

Set `MCPSHIELD_TELEMETRY_ENABLED=true`, `OTEL_SERVICE_NAME=mcpshield-gateway`, and the configured OTLP collector URL to export bounded admission spans/counters/latency. W3C trace context propagates to the admission API; no credentials, request arguments, or response bodies are telemetry attributes.
