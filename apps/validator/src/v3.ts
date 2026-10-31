// Independent validator for ReleaseRegistryV3 (ADR-008). Unlike v2.ts it never signs the operator's report:
// it checks that its own copy of the artifact matches the identity on chain, scans that copy itself, writes its
// own evidence file, and signs the hash of that file with its own verdict. Disagreeing with the other validators
// is a valid outcome, not an error. Scope: local-source artifacts (the default policy); prepared/OCI stay on v2.ts.
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { Contract, JsonRpcProvider, Wallet, id } from "ethers";
import { attestationV3Domain, attestationV3Types, bytes32, createReleaseRegistryV3, exactReleaseIdentity,
  evidenceDocument, quarantineReason, verdictFromReport } from "../../../packages/contracts-sdk/src/v3.js";
import { boundedServiceRequest, checkedServiceUrl, v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";
// @ts-expect-error Resolver and scanner are shared ESM JavaScript.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Resolver and scanner are shared ESM JavaScript.
import { scanRelease } from "../../../services/scanner/src/scanner.mjs";

// The verdict rules and the evidence file live in the SDK so the operator API and auditors check the same bytes.
export { verdictFromFindings, verdictFromReport, quarantineReason, evidenceDocument, type V3Verdict } from "../../../packages/contracts-sdk/src/v3.js";
const VERDICT = { PASS: 0, FAIL: 1, ABSTAIN: 2 } as const;
export const MAX_ROUND_SECONDS = 86_400;

export interface ValidatorV3Options {
  privateKey: string; rpcUrl: string; chainId: number; registryAddress: string; policyHash: string;
  /** Direct mode: the release and the round window the operator announced; validators that agree on it land in one round.
   * Relay mode reads both from the operator's announcement instead. */
  releaseId?: string; validFrom?: number; validUntil?: number;
  artifactDir: string; baselineDir?: string;
  evidenceDir: string;
  /** Relayer key for gasless validators; omitted = the validator sends its own transaction. */
  relayerKey?: string;
  /** Operator relay: the API announces the round and pays gas, but the validator still builds and signs every field itself,
   * keeps its policy pinned, and confirms the relayed transaction on chain. Emergency quarantine stays a direct transaction. */
  relay?: { apiUrl: string; token: string; scanId: string };
  quarantine?: boolean; dryRun?: boolean;
  scan?: Record<string, unknown>;
  now?: () => Promise<number>;
}
type RelayRequest = (path: string, body?: unknown) => Promise<any>;

function relayClient(relay: NonNullable<ValidatorV3Options["relay"]>): RelayRequest {
  const base = checkedServiceUrl(relay.apiUrl);
  if (!relay.token || !/^[0-9a-f-]{36}$/.test(relay.scanId)) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  return async (path, body) => {
    const response = await boundedServiceRequest(new URL(path, base).href, { method: body === undefined ? "GET" : "POST",
      headers: { authorization: `Bearer ${relay.token}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`VALIDATOR_API_HTTP_${response.statusCode}`);
    return JSON.parse(response.body.toString());
  };
}

/** Waits for the operator's outbox and checks on chain that the mined transaction carries exactly this signed vote. */
async function settleRelayed(request: RelayRequest, provider: JsonRpcProvider, registryAddress: string, actionId: string, calldata: string, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { action } = await request(`/v1/chain/actions/${actionId}`);
    if (action?.status === "FAILED") throw new Error("CHAIN_ACTION_FAILED");
    if (action?.status === "DEAD_LETTER") throw new Error("CHAIN_ACTION_REQUIRES_RECONCILIATION");
    if (action?.status === "COMPLETED" && /^0x[0-9a-f]{64}$/.test(action.txHash ?? "")) {
      const [tx, receipt] = await Promise.all([provider.getTransaction(action.txHash), provider.getTransactionReceipt(action.txHash)]);
      if (tx?.to?.toLowerCase() !== registryAddress.toLowerCase() || tx.data !== calldata || tx.value !== 0n || receipt?.status !== 1) throw new Error("VALIDATOR_CHAIN_CONFIRMATION_MISMATCH");
      return action.txHash as string;
    }
    await sleep(500);
  }
  throw new Error("CHAIN_CONFIRMATION_TIMEOUT");
}

export async function runValidatorV3(options: ValidatorV3Options) {
  if (!Number.isSafeInteger(options.chainId) || options.chainId <= 0 || !/^0x[0-9a-fA-F]{40}$/.test(options.registryAddress)
    || !/^0x[0-9a-f]{64}$/.test(options.policyHash)) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  const request = options.relay ? relayClient(options.relay) : undefined;
  const provider = new JsonRpcProvider(v2RpcRequest(options.rpcUrl), undefined, { batchMaxCount: 1, cacheTimeout: -1 });
  try {
    if ((await provider.getNetwork()).chainId !== BigInt(options.chainId)) throw new Error("CHAIN_ID_MISMATCH");
    const wallet = new Wallet(options.privateKey, provider);
    let { releaseId, validFrom, validUntil } = options;
    if (request) {
      // Only the round is taken from the operator; the policy stays pinned here and every signed field is rebuilt below.
      const announced = await request(`/v1/scans/${options.relay!.scanId}/attestation?validator=${wallet.address}`);
      if (announced?.registryVersion !== 3 || announced.round?.policyHash !== options.policyHash) throw new Error("RELAY_ROUND_MISMATCH");
      ({ releaseId, validFrom, validUntil } = announced.round);
    }
    if (typeof releaseId !== "string" || !/^0x[0-9a-f]{64}$/.test(releaseId)) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
    const sender = options.relayerKey ? new Wallet(options.relayerKey, provider) : wallet;
    const registry: any = createReleaseRegistryV3(options.registryAddress, sender);
    const now = options.now ?? (async () => Number((await provider.getBlock("latest"))!.timestamp));
    const head = await now();
    if (!Number.isSafeInteger(validFrom) || !Number.isSafeInteger(validUntil) || validFrom! > head
      || validUntil! <= head || validUntil! <= validFrom! || validUntil! - validFrom! > MAX_ROUND_SECONDS) throw new Error("ROUND_WINDOW_INVALID");
    const validators = new Contract(await registry.validators(), ["function version() view returns(uint32)", "function isActiveValidator(address,uint32) view returns(bool)"], provider);
    const version = Number(await validators.version());
    if (!await validators.isActiveValidator(wallet.address, version)) throw new Error("NOT_VALIDATOR");
    // The oracle check: this validator's own bytes must be the bytes registered on chain.
    const onChain = await registry.releases(releaseId);
    if (!onChain.exists) throw new Error("RELEASE_NOT_REGISTERED");
    const local = await resolveArtifact({ sourceType: "local", locator: options.artifactDir });
    const release = { releaseId, artifactDigest: bytes32(local.artifactDigest), manifestDigest: bytes32(local.manifestDigest), toolSurfaceDigest: bytes32(local.toolSurfaceHash) };
    if (release.artifactDigest !== onChain.artifactDigest || release.manifestDigest !== onChain.manifestDigest || release.toolSurfaceDigest !== onChain.toolSurfaceDigest
      || exactReleaseIdentity({ toolId: onChain.toolId, ...local }).releaseId !== releaseId) throw new Error("ARTIFACT_IDENTITY_MISMATCH");
    const report = await scanRelease({ fixtureDir: options.artifactDir, baselineDir: options.baselineDir, sandbox: "local", logger: () => {}, ...options.scan });
    // The scanner works on its own snapshot; it must be the same bytes that were just matched to the chain.
    if (report.artifactDigest !== local.artifactDigest || bytes32(report.toolSurfaceHash) !== release.toolSurfaceDigest) throw new Error("ARTIFACT_CHANGED_DURING_SCAN");
    const verdict = verdictFromReport(report);
    const { file, evidenceHash } = evidenceDocument(wallet.address, release, report, verdict);
    await mkdir(options.evidenceDir, { recursive: true });
    const evidenceFile = join(options.evidenceDir, `${releaseId.slice(2, 14)}.${wallet.address.slice(2, 10).toLowerCase()}.${evidenceHash.slice(2, 14)}.json`);
    await writeFile(evidenceFile, file);
    const roundId: string = await registry.roundIdOf(releaseId, options.policyHash, validFrom, validUntil, version);
    const result: Record<string, any> = { validator: wallet.address, releaseId, verdict: verdict.verdict, basis: verdict.basis,
      evidenceHash, evidenceFile, roundId, transactions: [] as any[] };
    const reason = quarantineReason(report);
    if (options.quarantine && reason && !options.dryRun && Number(await registry.lastQuarantineAt(releaseId, wallet.address)) === 0
      && Number(await registry.quarantineUntil(releaseId)) <= head && !(await registry.revoked(releaseId))) {
      // A direct quarantine is sent by the validator itself so the operator cannot censor it.
      const direct: any = createReleaseRegistryV3(options.registryAddress, wallet);
      const receipt = await (await direct.quarantine(releaseId, options.policyHash, evidenceHash, id(reason), BigInt(head + 3600))).wait();
      result.transactions.push({ kind: "QUARANTINE", reason, txHash: receipt.hash });
    }
    if ((await registry.getVote(roundId, wallet.address)).cast) return { ...result, skipped: "ALREADY_VOTED" };
    const payload = { ...release, policyHash: options.policyHash, evidenceHash, verdict: VERDICT[verdict.verdict], validFrom: validFrom!,
      validUntil: validUntil!, validatorSetVersion: version, nonce: Number(await registry.nonces(wallet.address)), deadline: Math.min((await now()) + 1800, validUntil!) };
    // Only the pinned local V3 types and the locally built payload are ever signed.
    const signature = await wallet.signTypedData(attestationV3Domain(options.chainId, options.registryAddress), attestationV3Types, payload);
    if (options.dryRun) return { ...result, payload, signature };
    if (request) {
      // The operator relays and pays gas; the evidence file goes along so anyone can re-hash it against the signed evidenceHash.
      const { action } = await request("/v1/validator/attestations", { scanId: options.relay!.scanId, payload, signature, evidence: file });
      const calldata = registry.interface.encodeFunctionData("submitAttestation", [payload, signature]);
      result.transactions.push({ kind: "ATTEST", relayed: true, txHash: await settleRelayed(request, provider, options.registryAddress, action.actionId, calldata) });
      return result;
    }
    const receipt = await (await registry.submitAttestation(payload, signature)).wait();
    result.transactions.push({ kind: "ATTEST", txHash: receipt.hash });
    return result;
  } finally { provider.destroy(); }
}

async function main() {
  const env = process.env;
  // CONTROL_SCAN_ID selects the operator relay; without it the round comes from VALIDATOR_RELEASE_ID and VALIDATOR_VALID_*.
  const relay = env.CONTROL_SCAN_ID ? { apiUrl: env.CONTROL_API_URL ?? "", token: env.CONTROL_API_TOKEN ?? "", scanId: env.CONTROL_SCAN_ID } : undefined;
  const required = ["VALIDATOR_PRIVATE_KEY", "CONTROL_V2_RPC_URLS", "CONTROL_V2_CHAIN_ID", "CONTROL_V3_REGISTRY_ADDRESS", "CONTROL_VALIDATOR_POLICY_HASH",
    "VALIDATOR_ARTIFACT_DIR", "VALIDATOR_EVIDENCE_DIR", ...(relay ? ["CONTROL_API_URL", "CONTROL_API_TOKEN"] : ["VALIDATOR_RELEASE_ID", "VALIDATOR_VALID_FROM", "VALIDATOR_VALID_UNTIL"])];
  if (required.some((name) => !env[name])) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  const args = process.argv.slice(2);
  if (args.some((arg) => !["--quarantine", "--dry-run"].includes(arg))) throw new Error("VALIDATOR_MODE_INVALID");
  console.log(JSON.stringify(await runValidatorV3({ privateKey: env.VALIDATOR_PRIVATE_KEY!, rpcUrl: env.CONTROL_V2_RPC_URLS!.split(",")[0],
    chainId: Number(env.CONTROL_V2_CHAIN_ID), registryAddress: env.CONTROL_V3_REGISTRY_ADDRESS!, policyHash: env.CONTROL_VALIDATOR_POLICY_HASH!,
    releaseId: relay ? undefined : env.VALIDATOR_RELEASE_ID, artifactDir: env.VALIDATOR_ARTIFACT_DIR!, baselineDir: env.VALIDATOR_BASELINE_DIR || undefined,
    validFrom: relay ? undefined : Number(env.VALIDATOR_VALID_FROM), validUntil: relay ? undefined : Number(env.VALIDATOR_VALID_UNTIL), evidenceDir: env.VALIDATOR_EVIDENCE_DIR!,
    relayerKey: env.VALIDATOR_RELAYER_PRIVATE_KEY || undefined, relay, quarantine: args.includes("--quarantine"), dryRun: args.includes("--dry-run") })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => {
  console.error(/^[A-Z_]+$/.test(error?.message ?? "") ? error.message : "VALIDATOR_OPERATION_FAILED"); process.exitCode = 1;
});
