# MCPShield Gateway

The Gateway accepts an artifact directory, never a caller-provided release ID, digest, tool hash, executable, or arguments. It copies regular files into a private temporary snapshot, computes the scanner-compatible artifact and tool-surface hashes from those exact bytes, validates the `.mjs` manifest entrypoint, checks admission, and starts only that snapshotted entrypoint with the current Node executable.

The child receives only a minimal system environment. Pass an MCP-specific variable intentionally by listing its exact name in `MCPSHIELD_CHILD_ENV_ALLOWLIST`; unrelated parent secrets are not inherited. Runtime injection variables such as `NODE_OPTIONS`, `NODE_PATH`, `LD_*`, and `DYLD_*` are always removed. Artifact code is ESM-only: `.js`, CommonJS, dynamic, absolute, package, native, and WebAssembly module loads are rejected. Loader-shaped raw source is rejected fail-closed so regex or template syntax cannot hide a dynamic import. `.mjs` code may use only an allowlist of non-network `node:` built-ins and relative `.mjs` modules captured inside its snapshot. Node's permission model prevents reads outside that snapshot, string code generation is disabled, child output is capped, and runtime network egress is not supported by this MVP.

```powershell
npm.cmd run test:gateway
node apps/gateway/src/index.mjs run --artifact demo/fixtures/mail-mcp-1.0.0 --mode replay --replay scripts/demo/replay.json
node apps/gateway/src/index.mjs run --artifact demo/fixtures/mail-mcp-1.0.1 --mode replay --replay scripts/demo/replay.json
```

For MCP stdio mode set `MCPSHIELD_ARTIFACT_DIR`, `MCPSHIELD_MODE`, `MCPSHIELD_API_URL`, and optionally `MCPSHIELD_ADMISSION_TIMEOUT_MS` or `MCPSHIELD_REPLAY_FILE`. The Gateway relays newline-delimited JSON-RPC bytes while observing request IDs. It fully checks JSON-RPC batches, allows only manifest-declared `tools/call` names, and suppresses duplicate or mismatched `tools/list` responses before terminating the child fail-closed.

Symlinks, traversal entrypoints, non-JavaScript entrypoints, oversized artifacts, arbitrary commands, command arguments, shells, `npx`, and caller-supplied identity values are not accepted. Stop the Gateway service to disable spawning. REPLAY is demo-only and verifies its saved artifact identity; MOCK is display-only and always returns BLOCK in the Gateway.
