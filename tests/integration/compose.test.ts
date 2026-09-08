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
  assert.match(compose, /chown node:node \/deployment \/data.*su node.*chmod 0750 \/deployment \/data/);
  assert.match(compose, /x-security: &security[\s\S]*cap_drop:\s*\n\s*- ALL/);
  assert.match(compose, /contract-init:\s*\n\s*<<: \*security\s*\n\s*cap_add:\s*\n\s*- CHOWN\s*\n\s*- SETGID\s*\n\s*- SETUID/);
  assert.match(compose, /gateway-a:[\s\S]*gateway-a\.json/);
  assert.match(compose, /gateway-b:[\s\S]*gateway-b\.json/);
  assert.match(compose, /gateway-a:[\s\S]*gateway-evidence-a:\/evidence/);
  assert.match(compose, /gateway-b:[\s\S]*gateway-evidence-b:\/evidence/);
  assert.match(compose, /dashboard:[\s\S]*gateway-evidence-a:\/evidence\/gateway-a:ro[\s\S]*gateway-evidence-b:\/evidence\/gateway-b:ro/);
  assert.doesNotMatch(compose, /gateway-evidence:\/evidence/);
  assert.match(compose, /x-gateway: &gateway[\s\S]*\/tmp:rw,noexec,nosuid/);
  assert.match(compose, /demo-seed:[\s\S]*?tmpfs:\s*\n\s*- \/tmp:rw,noexec,nosuid,size=32m,mode=1777[\s\S]*?dashboard:/);
  assert.match(compose, /dashboard:[\s\S]*MCPSHIELD_GATEWAY_EVIDENCE_DIR: \/evidence/);
  assert.match(compose, /x-backend-env: &backend-env[\s\S]*MCPSHIELD_JUDGE_DEMO_ENABLED: "true"/);
  assert.doesNotMatch(compose, /chmod 0777|MCPSHIELD_SCAN_IDS/);
  assert.doesNotMatch(compose, /ATTESTATION_CONTRACT: 0x0{39}1/);
});

test('persistent control plane separates private storage and cannot spawn host containers', () => {
  const compose = readFileSync(new URL('../../compose.control.yml', import.meta.url), 'utf8');
  assert.match(compose, /CONTROL_DATABASE_URL: postgresql:\/\//);
  assert.match(compose, /control-postgres:[\s\S]*pg_isready/);
  assert.match(compose, /control-init:[\s\S]*chown node:node.*su node.*chmod 0700/);
  assert.match(compose, /control-worker:[\s\S]*control-worker-cli\.ts/);
  assert.match(compose, /control-artifacts:\/control-artifacts:ro/);
  assert.match(compose, /cap_drop: \[ALL\]/);
  assert.doesNotMatch(compose, /\/var\/run\/docker\.sock|privileged:\s*true|chmod 0777/);
  assert.doesNotMatch(compose.split('  control-init:')[0], /ports:/);
});

test('Gateway image includes OCI validation dependencies and checks imports without adding host Docker authority', () => {
  const dockerfile = readFileSync(new URL('../../apps/gateway/Dockerfile', import.meta.url), 'utf8');
  for (const path of ['services/scanner/src', 'services/resolver/src', 'packages/protocol/schemas'])
    assert.ok(dockerfile.includes(`COPY ${path} ./${path}`), path);
  assert.match(dockerfile, /USER node[\s\S]*RUN MCPSHIELD_TELEMETRY_ENABLED=false node --input-type=module -e "await import\('\.\/services\/resolver\/src\/oci-runtime\.mjs'\)"/);
  assert.doesNotMatch(dockerfile, /apk add[^\n]*docker|\/var\/run\/docker\.sock|USER root/);
});
