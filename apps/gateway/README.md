# MCPShield Gateway

The Gateway accepts an artifact directory, never a caller-provided release ID, digest, tool hash, executable, or arguments. It copies regular files into a private temporary snapshot, computes the scanner-compatible artifact and tool-surface hashes from those exact bytes, validates the manifest entrypoint, checks admission, and starts only that snapshotted entrypoint with the current Node executable.

```powershell
npm.cmd run test:gateway
node apps/gateway/src/index.mjs run --artifact demo/fixtures/mail-mcp-1.0.0 --mode replay --replay scripts/demo/replay.json
node apps/gateway/src/index.mjs run --artifact demo/fixtures/mail-mcp-1.0.1 --mode replay --replay scripts/demo/replay.json
```

For MCP stdio mode set `MCPSHIELD_ARTIFACT_DIR`, `MCPSHIELD_MODE`, `MCPSHIELD_API_URL`, and optionally `MCPSHIELD_ADMISSION_TIMEOUT_MS` or `MCPSHIELD_REPLAY_FILE`. The Gateway relays newline-delimited JSON-RPC bytes while observing request IDs. A `tools/list` response whose canonical tool surface differs from the admitted manifest is suppressed and the child is terminated fail-closed.

Symlinks, traversal entrypoints, non-JavaScript entrypoints, oversized artifacts, arbitrary commands, command arguments, shells, `npx`, and caller-supplied identity values are not accepted. Stop the Gateway service to disable spawning. REPLAY is demo-only and verifies its saved artifact identity; MOCK is display-only and always returns BLOCK in the Gateway.
