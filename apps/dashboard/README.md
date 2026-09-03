# MCPShield Dashboard

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:3000`. MOCK works without a backend. LIVE reads only the frozen `GET /api/releases/:releaseId` and `GET /api/events` interfaces; on timeout it switches to a clearly labeled REPLAY snapshot.

Set `MCPSHIELD_API_URL` for LIVE and `MCPSHIELD_REPLAY_FILE` for an alternate replay bundle. Roll back by selecting MOCK/REPLAY or stopping the dashboard container.
