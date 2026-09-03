import { HDNodeWallet, id } from "ethers";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanRelease } from "../../services/scanner/src/scanner.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const expected = JSON.parse(await readFile(resolve(root, "demo/fixtures/expected-hashes.json"), "utf8")).fixtures;

const apiUrl = (process.env.MCPSHIELD_API_URL ?? "http://127.0.0.1:3001").replace(/\/$/, "");
const adminToken = process.env.ADMIN_API_TOKEN ?? "dev_admin_token_32_characters";
const scannerToken = process.env.SCANNER_API_TOKEN ?? "dev_scanner_token_32_characters";
const chainId = Number(process.env.ATTESTATION_CHAIN_ID ?? 31337);
const verifyingContract = process.env.ATTESTATION_CONTRACT ?? "0x0000000000000000000000000000000000000001";
const demoMnemonic = process.env.DEMO_VALIDATOR_MNEMONIC ?? "test test test test test test test test test test test junk";
const validatorWallets = [1, 2].map((index) => HDNodeWallet.fromPhrase(demoMnemonic, undefined, `m/44'/60'/0'/0/${index}`));

const releases = [
  { releaseId: "mail-mcp@1.0.0", fixtureDir: resolve(root, "demo/fixtures/mail-mcp-1.0.0"), decision: "PASS", expectedStatus: "VERIFIED", nonce: 0 },
  { releaseId: "mail-mcp@1.0.1", fixtureDir: resolve(root, "demo/fixtures/mail-mcp-1.0.1"), baselineDir: resolve(root, "demo/fixtures/mail-mcp-1.0.0"), decision: "FAIL", expectedStatus: "REVOKED", nonce: 1 },
];

const domain = { name: "MCPShield", version: "1", chainId, verifyingContract };
const types = { Attestation: [
  { name: "releaseKey", type: "bytes32" },
  { name: "decision", type: "uint8" },
  { name: "evidenceHash", type: "bytes32" },
  { name: "nonce", type: "uint256" },
  { name: "deadline", type: "uint256" },
] };

async function request(path, { token, body, allow = [] } = {}) {
  const response = await fetch(`${apiUrl}${path}`, {
    method: body ? "POST" : "GET",
    headers: { accept: "application/json", ...(body ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(5_000),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok && !allow.includes(response.status)) throw new Error(`${path} returned ${response.status}: ${JSON.stringify(payload)}`);
  return { status: response.status, payload };
}

for (const release of releases) {
  const identity = expected[release.releaseId];
  if (!identity) throw new Error(`Expected fixture identity is missing for ${release.releaseId}`);
  const scan = await scanRelease({ fixtureDir: release.fixtureDir, baselineDir: release.baselineDir, sandbox: "local", source: "LIVE" });
  if (scan.artifactDigest !== identity.artifactDigest || scan.toolSurfaceHash !== identity.toolSurfaceHash) throw new Error(`Fixture identity drifted for ${release.releaseId}`);
  await request("/api/releases", { token: adminToken, allow: [200, 201], body: { schemaVersion: "1.0.0", releaseId: release.releaseId, ...identity } });
  await request("/api/scans", { token: scannerToken, allow: [201], body: scan });

  const current = await request(`/api/releases/${encodeURIComponent(release.releaseId)}`);
  if (current.payload.release?.status !== release.expectedStatus) {
    const deadline = Math.floor(Date.now() / 1000) + 600;
    for (const signer of validatorWallets) {
      const value = { releaseKey: id(release.releaseId), decision: release.decision === "PASS" ? 0 : 1, evidenceHash: scan.evidenceHash, nonce: release.nonce, deadline };
      const signature = await signer.signTypedData(domain, types, value);
      await request("/api/validators/vote", { allow: [200, 201], body: { schemaVersion: "1.0.0", releaseId: release.releaseId, scanId: scan.scanId, decision: release.decision, evidenceHash: scan.evidenceHash, nonce: release.nonce, deadline, signature } });
    }
  }
}

const summary = await Promise.all(releases.map(async ({ releaseId }) => (await request(`/api/releases/${encodeURIComponent(releaseId)}`)).payload.release));
console.log(JSON.stringify({ source: "LIVE", seeded: summary }, null, 2));
