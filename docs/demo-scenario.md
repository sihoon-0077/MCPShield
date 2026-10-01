# MCPShield Demo Scenario

## Fixtures

- Safe: `mail-mcp@1.0.0`
- Malicious signed update: `mail-mcp@1.0.1`
- Canary and sink are synthetic and local only.

## 3-minute script

1. Open the dashboard in `LIVE` mode and show the safe `1.0.0` release.
2. Explain that the exact artifact and tool-surface hashes are bound to the release.
3. Show the static, AI, and sandbox pipeline for `1.0.1`.
4. Point out `SEMANTIC_BEHAVIOR_MISMATCH` and `CANARY_EXFILTRATION` evidence.
5. Show two independent `FAIL` votes and the `REVOKED` status.
6. Connect the official MCP client through Gateway A, list `mail-mcp@1.0.0` tools, and call `list_messages`.
7. Run the malicious release through Gateway A and Gateway B: both return exit code 3 and emit no child marker.
8. Finish with: `Registry: Available · Signature: Valid · MCPShield: REVOKED · Agent: BLOCKED`.

## Reproducible commands

```powershell
npm.cmd ci
npm.cmd run demo:mcp-e2e
npm.cmd run demo:smoke
npm.cmd run demo:live-smoke
npm.cmd run benchmark:security
```

`demo:mcp-e2e` uses the official MCP TypeScript client to prove the stdio handshake, tool discovery, tool call, and pre-spawn block. `demo:smoke` is an offline REPLAY fallback. `demo:live-smoke` starts an ephemeral real Backend and proves the API, signatures, quorum, admission decision, and pre-spawn enforcement without Docker.

For the dashboard and two long-running gateways:

```powershell
npm.cmd run stack:up
# Open http://localhost:3000
npm.cmd run stack:down
```

## Expected results

| Path | Scan | Votes | Status | Gateway |
|---|---|---|---|---|
| `1.0.0` safe | `PASSED` | A/B `PASS` | `VERIFIED` | `ALLOW`, MCP tool call succeeds |
| `1.0.1` malicious | `FAILED` | A/B `FAIL` | `REVOKED` | `BLOCK`, child never starts |

## Failure recovery

- Docker or network failure: run `npm.cmd run demo:smoke` and keep the `REPLAY` badge visible.
- Backend or chain lookup failure in LIVE mode: Gateway returns a non-zero error and does not spawn.
- Dashboard LIVE fetch failure: the UI shows a source-labelled error instead of silently substituting replay data.
- Demo reset: `npm.cmd run demo:reset` restores the committed replay snapshot.

## Safety notes

- Never substitute real customer data or real credentials in the malicious fixture.
- The fixed mnemonic and tokens in demo/Compose scripts are public localhost-only values.
- Do not expose demo ports beyond loopback.
- Stop all services after the presentation.
