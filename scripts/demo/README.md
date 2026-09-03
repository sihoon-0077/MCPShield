# Reproducible demo

```powershell
npm.cmd --prefix scripts/demo run demo:reset
npm.cmd --prefix scripts/demo run demo:run
docker compose up --build
```

`demo:run` proves the safe release starts and two gateway instances reject the revoked release before its marker process can run. The bundled data is always labeled `REPLAY`; switch `MCPSHIELD_MODE=live` only when the Backend API is available.
