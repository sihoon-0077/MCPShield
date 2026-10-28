// Small public-testnet demo set for ReleaseRegistryV3 (ADR-008): approve, emergency quarantine, revoke.
// Reads keys from MCPSHIELD_SECRETS_DIR (never printed) and the deployment record, scans the real mail fixtures
// once per validator, writes each validator's evidence file and the transaction record under benchmarks/results.
// Policy, registration, quarantine and duplicate votes are checked on chain first; a re-run opens new vote rounds.
//
//   MCPSHIELD_SECRETS_DIR=... node --import tsx scripts/demo/base-sepolia-v3-demo.ts [--dry-run]
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { JsonRpcProvider, NonceManager, Wallet, id } from "ethers";
import { defaultPolicy } from "../../apps/api/src/control-policy.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { attestationV3Domain, attestationV3Types, bytes32, createReleaseRegistryV3, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v3.js";
// @ts-expect-error Resolver is shared ESM JavaScript.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";

const repo = resolve(import.meta.dirname, "../..");
const dryRun = process.argv.includes("--dry-run");
const deployment = JSON.parse(readFileSync(join(repo, "deployments/base-sepolia-v3.json"), "utf8"));
const secrets = process.env.MCPSHIELD_SECRETS_DIR;
if (!secrets) throw new Error("MCPSHIELD_SECRETS_DIR_REQUIRED");
const key = (name: string) => readFileSync(join(secrets, `${name}.key`), "utf8").trim();
const rpc = process.env.CONTROL_V2_RPC_URLS?.split(",")[0] ?? "https://sepolia.base.org";
const provider = new JsonRpcProvider(rpc, deployment.chainId, { staticNetwork: true, batchMaxCount: 1 });
const relayer = new NonceManager(new Wallet(key("deployer-relayer"), provider));
const validators = { A: new Wallet(key("validator-a"), provider), B: new Wallet(key("validator-b"), provider), C: new Wallet(key("validator-c"), provider) };
const registry: any = createReleaseRegistryV3(deployment.releaseRegistry.address, relayer);
const policies: any = new (await import("ethers")).Contract(deployment.policyRegistry.address,
  ["function publish(bytes32,bytes32)", "function policies(bytes32) view returns(bytes32 documentDigest,uint64 publishedAt,bool deprecated)"], relayer);
const domain = attestationV3Domain(deployment.chainId, deployment.releaseRegistry.address);
const STATUS = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"], VERDICT = { PASS: 0, FAIL: 1, ABSTAIN: 2 } as const;
const tx = (hashValue: string) => `https://sepolia.basescan.org/tx/${hashValue}`;
const day = new Date().toISOString().slice(0, 10);
const outDir = join(repo, "benchmarks/results", `base-sepolia-v3-demo-${day}`);
mkdirSync(outDir, { recursive: true });
const record: any = { network: "base-sepolia", chainId: deployment.chainId, registry: deployment.releaseRegistry.address, rpc, steps: [] };
const step = async (label: string, send: () => Promise<any>) => {
  if (dryRun) { record.steps.push({ label, dryRun: true }); console.log(`DRY ${label}`); return; }
  const receipt = await (await send()).wait();
  record.steps.push({ label, txHash: receipt.hash, block: receipt.blockNumber, url: tx(receipt.hash) });
  console.log(`${label}: ${tx(receipt.hash)}`);
};

// Each validator runs the scanner itself; its evidence is its own report plus its address, hashed as written.
function scanAs(validator: keyof typeof validators, fixture: string, baseline?: string) {
  const args = ["services/scanner/src/cli.mjs", "--fixture", fixture, ...(baseline ? ["--baseline", baseline] : [])];
  const out = execFileSync(process.execPath, args, { cwd: repo, stdio: ["ignore", "pipe", "ignore"] }).toString();
  const report = JSON.parse(out.slice(out.indexOf("{\n")));
  const file = `${JSON.stringify({ validator: validators[validator].address, report }, null, 2)}\n`;
  const name = `${report.releaseId.replace(/[^a-z0-9.-]/gi, "_")}.validator-${validator}.json`;
  writeFileSync(join(outDir, name), file);
  return { report, evidenceHash: `0x${createHash("sha256").update(file).digest("hex")}`, file: name };
}

const policyHash = hash(defaultPolicy);
record.policyHash = policyHash;
if ((await policies.policies(policyHash)).publishedAt === 0n) await step("publish default policy", () => policies.publish(policyHash, policyHash));

const releases: Record<string, any> = {};
for (const [label, dir] of [["safe", "demo/fixtures/mail-mcp-1.0.0"], ["malicious", "demo/fixtures/mail-mcp-1.0.1"]]) {
  const resolved = await resolveArtifact({ sourceType: "local", locator: join(repo, dir) });
  const exact = exactReleaseIdentity(resolved);
  releases[label] = { ...exact, artifactDigest: bytes32(resolved.artifactDigest), manifestDigest: bytes32(resolved.manifestDigest),
    toolSurfaceDigest: bytes32(resolved.toolSurfaceHash), version: resolved.version, fixture: dir };
  if (!(await registry.releases(exact.releaseId)).exists)
    await step(`register ${label} ${resolved.version}`, () => registry.registerRelease(exact.toolId, releases[label].artifactDigest, releases[label].manifestDigest, releases[label].toolSurfaceDigest));
}
record.releases = releases;

const head = async () => Number((await provider.getBlock("latest"))!.timestamp);
const vote = async (who: keyof typeof validators, release: any, verdict: keyof typeof VERDICT, window: { validFrom: number; validUntil: number }, evidenceHash: string, note?: string) => {
  const signer = validators[who], now = await head();
  const payload = { releaseId: release.releaseId, artifactDigest: release.artifactDigest, manifestDigest: release.manifestDigest,
    toolSurfaceDigest: release.toolSurfaceDigest, policyHash, evidenceHash, verdict: VERDICT[verdict], ...window,
    validatorSetVersion: 1, nonce: Number(await registry.nonces(signer.address)), deadline: now + 1800 };
  const roundId = await registry.roundIdOf(release.releaseId, policyHash, window.validFrom, window.validUntil, 1);
  if ((await registry.getVote(roundId, signer.address)).cast) { console.log(`skip ${who} ${verdict}: already voted`); return; }
  const signature = await signer.signTypedData(domain, attestationV3Types, payload);
  await step(`validator ${who} ${verdict} ${release.version}${note ? ` (${note})` : ""}`, () => registry.submitAttestation(payload, signature));
};

// Approve 1.0.0: A and B PASS on their own scans; C's ABSTAIN after the decision is a scripted dissent, labelled as such.
const safeScans = { A: scanAs("A", releases.safe.fixture), B: scanAs("B", releases.safe.fixture), C: scanAs("C", releases.safe.fixture) };
const t0 = await head(), sw = { validFrom: t0 - 5, validUntil: t0 - 5 + 86_400 };
record.safeWindow = sw;
for (const who of ["A", "B"] as const) await vote(who, releases.safe, safeScans[who].report.scanStatus === "PASSED" ? "PASS" : "FAIL", sw, safeScans[who].evidenceHash);
await vote("C", releases.safe, "ABSTAIN", sw, safeScans.C.evidenceHash, "scripted dissent for the demo; C's own scan passed");

// 1.0.1: validator C quarantines directly from its own key (no operator), then A and B FAIL revoke it; C's FAIL lands after the decision.
const badScans = { A: scanAs("A", releases.malicious.fixture, releases.safe.fixture), B: scanAs("B", releases.malicious.fixture, releases.safe.fixture),
  C: scanAs("C", releases.malicious.fixture, releases.safe.fixture) };
const canary = badScans.C.report.findings.find((f: any) => f.code === "CANARY_EXFILTRATION" && f.deterministic && f.stage === "SANDBOX");
if (!canary) throw new Error("NO_DETERMINISTIC_CANARY_FINDING");
if (!(await registry.revoked(releases.malicious.releaseId)) && Number(await registry.lastQuarantineAt(releases.malicious.releaseId, validators.C.address)) === 0) {
  const direct: any = createReleaseRegistryV3(deployment.releaseRegistry.address, validators.C);
  await step("validator C quarantine 1.0.1 directly (CANARY_EXFILTRATION)", async () =>
    direct.quarantine(releases.malicious.releaseId, policyHash, badScans.C.evidenceHash, id("CANARY_EXFILTRATION"), BigInt((await head()) + 3600)));
}
const t1 = await head(), bw = { validFrom: t1 - 5, validUntil: t1 - 5 + 86_400 };
record.maliciousWindow = bw;
for (const who of ["A", "B", "C"] as const) await vote(who, releases.malicious, badScans[who].report.scanStatus === "FAILED" ? "FAIL" : "PASS", bw, badScans[who].evidenceHash);

record.evidenceFiles = { safe: Object.fromEntries(Object.entries(safeScans).map(([k, v]) => [k, { file: v.file, evidenceHash: v.evidenceHash }])),
  malicious: Object.fromEntries(Object.entries(badScans).map(([k, v]) => [k, { file: v.file, evidenceHash: v.evidenceHash }])) };
const reader = createReleaseRegistryV3(deployment.releaseRegistry.address, provider);
record.final = {};
for (const [label, release] of dryRun ? [] : Object.entries(releases)) {
  const d = await reader.getDecision(release.releaseId, policyHash);
  record.final[label] = { status: STATUS[Number(d.status)], roundId: d.reportRoot, approvals: Number(d.approvals), rejections: Number(d.rejections) };
}
console.log(JSON.stringify(record.final));
if (!dryRun) writeFileSync(join(outDir, "transactions.json"), `${JSON.stringify(record, null, 2)}\n`);
provider.destroy();
