import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: { output: { type: 'string', default: '.env.master.local' } } });
const destination = resolve(values.output);
const token = () => randomBytes(32).toString('hex');
const keys = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const credentials = ['admin', 'operator', 'reader'].map((role) => ({ token: token(), tenantId: 'local-demo', role }));
const entries = {
  ADMIN_API_TOKEN: token(), SCANNER_API_TOKEN: token(),
  API_HOST: '127.0.0.1', API_PORT: '3301', CORS_ALLOWLIST: 'http://127.0.0.1:3300,http://localhost:3300',
  DATABASE_PATH: ':memory:', MCPSHIELD_JUDGE_DEMO_ENABLED: 'true',
  // Public development addresses only; no chain wallet key is generated or deployed here.
  VALIDATOR_ADDRESSES: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906',
  ATTESTATION_CHAIN_ID: '31337', ATTESTATION_CONTRACT: '0x0000000000000000000000000000000000000001',
  CONTROL_PLANE_ENABLED: 'true', CONTROL_PLANE_CREDENTIALS: JSON.stringify(credentials),
  CONTROL_DATABASE_URL: 'data/control-plane.sqlite', CONTROL_ARTIFACT_PATH: 'data/control-artifacts',
  CONTROL_EVIDENCE_PATH: 'data/control-evidence', CONTROL_EVIDENCE_KEY: token(),
  CONTROL_SIGNING_KEY: keys.privateKey.trim(), CONTROL_SIGNING_KEY_ID: 'local-demo-v1',
  MCPSHIELD_CACHE_PUBLIC_KEY: keys.publicKey.trim(), MCPSHIELD_CACHE_KEY_ID: 'local-demo-v1',
  MCPSHIELD_TENANT_ID: 'local-demo', MCPSHIELD_API_URL: 'http://127.0.0.1:3301',
  MCPSHIELD_PUBLIC_ORIGIN: 'http://127.0.0.1:3300',
  MCPSHIELD_CONTROL_TOKEN: credentials[1].token, MCPSHIELD_ADMISSION_MODE: 'strict',
  POSTGRES_PASSWORD: token(), MCPSHIELD_TELEMETRY_ENABLED: 'false',
};
// Exclusive creation: re-running must not overwrite the evidence decryption key.
writeFileSync(destination, '# PRIVATE local control-plane configuration. Never commit or share.\n' +
  Object.entries(entries).map(([key, value]) => `${key}='${value}'`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
console.log(`Private local configuration created: ${destination}. Tokens and keys were not printed. No blockchain or external AI was provisioned.`);
