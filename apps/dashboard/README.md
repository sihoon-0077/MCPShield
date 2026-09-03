# MCPShield Dashboard

```powershell
npm.cmd ci
npm.cmd run dev --workspace @mcpshield/dashboard
```

Open `http://localhost:3000`. MOCK works without a backend. LIVE reads releases, latest scans, and events. In Compose it also validates Gateway A/B's shared pre-spawn probe evidence; without that configured evidence directory, Backend admission results are explicitly labeled as Backend results rather than Gateway execution. On timeout or malformed data it switches to a clearly labeled REPLAY snapshot and emits an accessible error alert.

Set `MCPSHIELD_API_URL` for LIVE, `MCPSHIELD_REPLAY_FILE` for an alternate replay bundle, `MCPSHIELD_GATEWAY_EVIDENCE_DIR` for Gateway probe files, and optionally `MCPSHIELD_EXPLORER_URL` for EVM transaction links. LIVE automatically reads `GET /api/releases/:releaseId/scans/latest`, so every new random scanner result replaces the displayed evidence without configuration. Unconfigured or invalid explorer URLs are never rendered as links.

`lib/backend-client.ts` is the server-only integration boundary for all seven frozen Backend APIs: release register/get, scan submit/get, validator vote, admission check, and event listing. The dashboard view intentionally calls only read/admission operations; privileged mutations remain available to the demo seeder and scanner rather than browser code, so admin/scanner credentials are never bundled into the client.

Roll back by selecting MOCK/REPLAY or stopping the dashboard container.
