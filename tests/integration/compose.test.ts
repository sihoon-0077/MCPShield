import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

test("Compose wires a deployed registry into EVM backend and indexer", () => {
  const compose = readFileSync(new URL("../../docker-compose.yml", import.meta.url), "utf8");
  assert.match(compose, /contract-init:[\s\S]*DEPLOYMENT_ENV_PATH: \/deployment\/registry\.env/);
  assert.match(compose, /backend:[\s\S]*\. \/deployment\/registry\.env[\s\S]*ledgerMode!=='EVM'/);
  assert.match(compose, /indexer:[\s\S]*npm run start:indexer[\s\S]*condition: service_healthy/);
  assert.match(compose, /projection:\/data/);
  assert.match(compose, /--wallet\.mnemonic/);
  assert.match(compose, /chmod 0750 \/deployment \/data.*su node/);
  assert.match(compose, /x-security: &security[\s\S]*cap_drop:\s*\n\s*- ALL/);
  assert.match(compose, /contract-init:\s*\n\s*<<: \*security\s*\n\s*cap_add:\s*\n\s*- CHOWN\s*\n\s*- SETGID\s*\n\s*- SETUID/);
  assert.match(compose, /gateway-a:[\s\S]*gateway-a\.json/);
  assert.match(compose, /gateway-b:[\s\S]*gateway-b\.json/);
  assert.match(compose, /dashboard:[\s\S]*MCPSHIELD_GATEWAY_EVIDENCE_DIR: \/evidence/);
  assert.doesNotMatch(compose, /chmod 0777|MCPSHIELD_SCAN_IDS/);
  assert.doesNotMatch(compose, /ATTESTATION_CONTRACT: 0x0{39}1/);
});
