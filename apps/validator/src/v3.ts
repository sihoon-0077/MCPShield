// Independent validator for ReleaseRegistryV3 (ADR-008). Unlike v2.ts it never signs the operator's report:
// it checks that its own copy of the artifact matches the identity on chain, scans that copy itself, writes its
// own evidence file, and signs the hash of that file with its own verdict. Disagreeing with the other validators
// is a valid outcome, not an error. Scope: local-source artifacts (the default policy); prepared/OCI stay on v2.ts.
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Contract, JsonRpcProvider, Wallet, id } from "ethers";
import { attestationV3Domain, attestationV3Types, bytes32, createReleaseRegistryV3, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v3.js";
import { v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";
// @ts-expect-error Resolver and scanner are shared ESM JavaScript.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Resolver and scanner are shared ESM JavaScript.
import { scanRelease } from "../../../services/scanner/src/scanner.mjs";

export type V3Verdict = "PASS" | "FAIL" | "ABSTAIN";
const VERDICT = { PASS: 0, FAIL: 1, ABSTAIN: 2 } as const;
const QUARANTINE_REASONS = ["CANARY_EXFILTRATION", "HOST_ESCAPE_ATTEMPT", "DIGEST_MISMATCH"];
export const MAX_ROUND_SECONDS = 86_400;

/**
 * ADR-002 on one report: a deterministic non-AI HIGH/CRITICAL finding is a FAIL; a failed scan whose only
 * blocking findings come from AI (or are below HIGH) is ABSTAIN, because AI is a witness, never the judge.
 */
export function verdictFromReport(report: any): { verdict: V3Verdict; basis: string[] } {
  if (report?.scanStatus === "PASSED" && Array.isArray(report.findings)) return { verdict: "PASS", basis: [] };
  const findings: any[] = Array.isArray(report?.findings) ? report.findings : [];
  const hard = findings.filter((f) => f.deterministic === true && f.stage !== "AI" && ["HIGH", "CRITICAL"].includes(f.severity));
  if (hard.length) return { verdict: "FAIL", basis: [...new Set(hard.map((f) => f.code as string))] };
  return { verdict: "ABSTAIN", basis: [...new Set(findings.map((f) => f.code as string))] };
}

/** The deterministic sandbox finding that allows a one-validator emergency quarantine, if any. */
export function quarantineReason(report: any): string | null {
  const finding = (report?.findings ?? []).find((f: any) => f.deterministic === true && f.stage !== "AI" && f.severity === "CRITICAL"
    && QUARANTINE_REASONS.includes(f.code));
  return finding ? finding.code : null;
}

/** Evidence = this validator's own report bound to its address and the on-chain identity; the hash covers the exact bytes written. */
export function evidenceDocument(validator: string, release: { releaseId: string; artifactDigest: string; manifestDigest: string; toolSurfaceDigest: string },
  report: any, verdict: { verdict: V3Verdict; basis: string[] }) {
  const file = `${JSON.stringify({ schema: "mcpshield.validator-evidence.v3", validator, release, verdict: verdict.verdict, basis: verdict.basis, report }, null, 2)}\n`;
  return { file, evidenceHash: `0x${createHash("sha256").update(file).digest("hex")}` };
}

export interface ValidatorV3Options {
  privateKey: string; rpcUrl: string; chainId: number; registryAddress: string; policyHash: string;
  releaseId: string; artifactDir: string; baselineDir?: string;
  /** The round window the operator announced; validators that agree on it land in one round. */
  validFrom: number; validUntil: number;
  evidenceDir: string;
  /** Relayer key for gasless validators; omitted = the validator sends its own transaction. */
  relayerKey?: string;
  quarantine?: boolean; dryRun?: boolean;
  scan?: Record<string, unknown>;
  now?: () => Promise<number>;
}

export async function runValidatorV3(options: ValidatorV3Options) {
  if (!Number.isSafeInteger(options.chainId) || options.chainId <= 0 || !/^0x[0-9a-fA-F]{40}$/.test(options.registryAddress)
    || !/^0x[0-9a-f]{64}$/.test(options.policyHash) || !/^0x[0-9a-f]{64}$/.test(options.releaseId)) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  const provider = new JsonRpcProvider(v2RpcRequest(options.rpcUrl), undefined, { batchMaxCount: 1, cacheTimeout: -1 });
  try {
    if ((await provider.getNetwork()).chainId !== BigInt(options.chainId)) throw new Error("CHAIN_ID_MISMATCH");
    const wallet = new Wallet(options.privateKey, provider);
    const sender = options.relayerKey ? new Wallet(options.relayerKey, provider) : wallet;
    const registry: any = createReleaseRegistryV3(options.registryAddress, sender);
    const now = options.now ?? (async () => Number((await provider.getBlock("latest"))!.timestamp));
    const head = await now();
    if (!Number.isSafeInteger(options.validFrom) || !Number.isSafeInteger(options.validUntil) || options.validFrom > head
      || options.validUntil <= head || options.validUntil <= options.validFrom || options.validUntil - options.validFrom > MAX_ROUND_SECONDS) throw new Error("ROUND_WINDOW_INVALID");
    const validators = new Contract(await registry.validators(), ["function version() view returns(uint32)", "function isActiveValidator(address,uint32) view returns(bool)"], provider);
    const version = Number(await validators.version());
    if (!await validators.isActiveValidator(wallet.address, version)) throw new Error("NOT_VALIDATOR");
    // The oracle check: this validator's own bytes must be the bytes registered on chain.
    const onChain = await registry.releases(options.releaseId);
    if (!onChain.exists) throw new Error("RELEASE_NOT_REGISTERED");
    const local = await resolveArtifact({ sourceType: "local", locator: options.artifactDir });
    const release = { releaseId: options.releaseId, artifactDigest: bytes32(local.artifactDigest), manifestDigest: bytes32(local.manifestDigest), toolSurfaceDigest: bytes32(local.toolSurfaceHash) };
    if (release.artifactDigest !== onChain.artifactDigest || release.manifestDigest !== onChain.manifestDigest || release.toolSurfaceDigest !== onChain.toolSurfaceDigest
      || exactReleaseIdentity({ toolId: onChain.toolId, ...local }).releaseId !== options.releaseId) throw new Error("ARTIFACT_IDENTITY_MISMATCH");
    const report = await scanRelease({ fixtureDir: options.artifactDir, baselineDir: options.baselineDir, sandbox: "local", logger: () => {}, ...options.scan });
    // The scanner works on its own snapshot; it must be the same bytes that were just matched to the chain.
    if (report.artifactDigest !== local.artifactDigest || bytes32(report.toolSurfaceHash) !== release.toolSurfaceDigest) throw new Error("ARTIFACT_CHANGED_DURING_SCAN");
    const verdict = verdictFromReport(report);
    const { file, evidenceHash } = evidenceDocument(wallet.address, release, report, verdict);
    await mkdir(options.evidenceDir, { recursive: true });
    const evidenceFile = join(options.evidenceDir, `${options.releaseId.slice(2, 14)}.${wallet.address.slice(2, 10).toLowerCase()}.${evidenceHash.slice(2, 14)}.json`);
    await writeFile(evidenceFile, file);
    const roundId: string = await registry.roundIdOf(options.releaseId, options.policyHash, options.validFrom, options.validUntil, version);
    const result: Record<string, any> = { validator: wallet.address, releaseId: options.releaseId, verdict: verdict.verdict, basis: verdict.basis,
      evidenceHash, evidenceFile, roundId, transactions: [] as any[] };
    const reason = quarantineReason(report);
    if (options.quarantine && reason && !options.dryRun && Number(await registry.lastQuarantineAt(options.releaseId, wallet.address)) === 0
      && Number(await registry.quarantineUntil(options.releaseId)) <= head && !(await registry.revoked(options.releaseId))) {
      // A direct quarantine is sent by the validator itself so the operator cannot censor it.
      const direct: any = createReleaseRegistryV3(options.registryAddress, wallet);
      const receipt = await (await direct.quarantine(options.releaseId, options.policyHash, evidenceHash, id(reason), BigInt(head + 3600))).wait();
      result.transactions.push({ kind: "QUARANTINE", reason, txHash: receipt.hash });
    }
    if ((await registry.getVote(roundId, wallet.address)).cast) return { ...result, skipped: "ALREADY_VOTED" };
    const payload = { ...release, policyHash: options.policyHash, evidenceHash, verdict: VERDICT[verdict.verdict], validFrom: options.validFrom,
      validUntil: options.validUntil, validatorSetVersion: version, nonce: Number(await registry.nonces(wallet.address)), deadline: (await now()) + 1800 };
    // Only the pinned local V3 types and the locally built payload are ever signed.
    const signature = await wallet.signTypedData(attestationV3Domain(options.chainId, options.registryAddress), attestationV3Types, payload);
    if (options.dryRun) return { ...result, payload, signature };
    const receipt = await (await registry.submitAttestation(payload, signature)).wait();
    result.transactions.push({ kind: "ATTEST", txHash: receipt.hash });
    return result;
  } finally { provider.destroy(); }
}

async function main() {
  const env = process.env, required = ["VALIDATOR_PRIVATE_KEY", "CONTROL_V2_RPC_URLS", "CONTROL_V2_CHAIN_ID", "CONTROL_V3_REGISTRY_ADDRESS", "CONTROL_VALIDATOR_POLICY_HASH",
    "VALIDATOR_RELEASE_ID", "VALIDATOR_ARTIFACT_DIR", "VALIDATOR_VALID_FROM", "VALIDATOR_VALID_UNTIL", "VALIDATOR_EVIDENCE_DIR"];
  if (required.some((name) => !env[name])) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  const args = process.argv.slice(2);
  if (args.some((arg) => !["--quarantine", "--dry-run"].includes(arg))) throw new Error("VALIDATOR_MODE_INVALID");
  console.log(JSON.stringify(await runValidatorV3({ privateKey: env.VALIDATOR_PRIVATE_KEY!, rpcUrl: env.CONTROL_V2_RPC_URLS!.split(",")[0],
    chainId: Number(env.CONTROL_V2_CHAIN_ID), registryAddress: env.CONTROL_V3_REGISTRY_ADDRESS!, policyHash: env.CONTROL_VALIDATOR_POLICY_HASH!,
    releaseId: env.VALIDATOR_RELEASE_ID!, artifactDir: env.VALIDATOR_ARTIFACT_DIR!, baselineDir: env.VALIDATOR_BASELINE_DIR || undefined,
    validFrom: Number(env.VALIDATOR_VALID_FROM), validUntil: Number(env.VALIDATOR_VALID_UNTIL), evidenceDir: env.VALIDATOR_EVIDENCE_DIR!,
    relayerKey: env.VALIDATOR_RELAYER_PRIVATE_KEY || undefined, quarantine: args.includes("--quarantine"), dryRun: args.includes("--dry-run") })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => {
  console.error(/^[A-Z_]+$/.test(error?.message ?? "") ? error.message : "VALIDATOR_OPERATION_FAILED"); process.exitCode = 1;
});
