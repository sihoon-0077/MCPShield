# MCPShield Gateway

The gateway checks `POST /api/admission/check` before starting any MCP child process. It fails closed on invalid responses, network errors, and timeouts.

```powershell
npm.cmd install
npm.cmd test
node src/index.mjs run --release mail-mcp@1.0.0 --digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --mode mock -- node -e "console.log('safe MCP started')"
node src/index.mjs run --release mail-mcp@1.0.1 --digest sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --mode mock -- node -e "console.log('must never run')"
```

Use `npm start` as a transparent MCP stdio wrapper. Set `MCPSHIELD_RELEASE_ID`, `MCPSHIELD_ARTIFACT_DIGEST`, and a fixed JSON command such as `MCPSHIELD_COMMAND_JSON=["node","server.mjs"]`; the child inherits stdin/stdout only after release and digest admission. Production mode is `live`; set `MCPSHIELD_API_URL` and optionally `MCPSHIELD_ADMISSION_TIMEOUT_MS`. `MCPSHIELD_ALLOWED_COMMANDS` is a comma-separated executable allowlist.

To disable spawning without changing code, set `MCPSHIELD_ALLOWED_COMMANDS` to a non-existent executable name or stop the gateway service. Use `MCPSHIELD_MODE=replay` with `MCPSHIELD_REPLAY_FILE` only for an explicitly labeled offline demo.
