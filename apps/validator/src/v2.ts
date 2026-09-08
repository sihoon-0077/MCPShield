import { Contract, JsonRpcProvider, Wallet, id } from "ethers";
import { pathToFileURL } from "node:url";
import { setTimeout } from "node:timers/promises";
import { policyVerdict, validPolicy } from "../../api/src/control-policy.js";
import { hash } from "../../api/src/control-plane.js";
import { attestationV2Domain, attestationV2Types, bytes32, createReleaseRegistryV2, exactReleaseIdentity, quarantineV2Types } from "../../../packages/contracts-sdk/src/v2.js";
import { boundedServiceRequest, checkedServiceUrl, v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";
import { traceHeaders, withSpan } from "../../../packages/telemetry/index.mjs";
// @ts-expect-error Scanner evidence is shared ESM JavaScript.
import { verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";

interface ValidatorContext {
  chainId: number; registryAddress: string; policyHash: string; policy: any; scan: any; evidence: any;
  identity: any; validatorSetVersion: number; nonce: number; now?: number;
}
export function checkedValidatorPayload(template: any, context: ValidatorContext, quarantine = false) {
  const { scan, evidence, identity, policy } = context, now = context.now ?? Math.floor(Date.now() / 1000);
  const domain = attestationV2Domain(context.chainId, context.registryAddress), types = quarantine ? quarantineV2Types : attestationV2Types;
  const fail = () => { throw new Error("VALIDATOR_TEMPLATE_BINDING_MISMATCH"); };
  if (!template?.payload || hash(template.domain) !== hash(domain) || hash(template.types) !== hash(types)
    || Object.keys(template.payload).sort().join() !== Object.values(types)[0].map((field) => field.name).sort().join()) fail();
  if (!validPolicy(policy) || hash(policy) !== context.policyHash || scan.status !== "COMPLETED" || scan.policyHash !== context.policyHash
    || !scan.result || scan.result.reportRoot !== evidence.reportRoot || !verifyEvidenceBundle(evidence.bundle, evidence.reportRoot)) fail();
  const report = JSON.parse(evidence.bundle.files["report.json"]), verdict = policyVerdict(evidence.bundle, scan.result.scanResult);
  if (!identity.exists || identity.artifactDigest !== bytes32(report.artifactDigest) || identity.toolSurfaceDigest !== bytes32(report.toolSurfaceHash)
    || exactReleaseIdentity({ toolId: identity.toolId, artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest, toolSurfaceHash: identity.toolSurfaceDigest }).releaseId !== scan.releaseId) fail();
  const q = template.payload;
  if (!Number.isSafeInteger(context.nonce) || !Number.isSafeInteger(context.validatorSetVersion) || context.validatorSetVersion < 1
    || !Number.isSafeInteger(q.deadline) || q.deadline < now || q.deadline > now + 3600) fail();
  const common = { releaseId: scan.releaseId, policyHash: context.policyHash, validatorSetVersion: context.validatorSetVersion, nonce: context.nonce, deadline: q.deadline };
  let payload;
  if (quarantine) {
    const reason = report.findings.find((finding: any) => finding.deterministic === true && finding.stage !== "AI" && finding.severity === "CRITICAL"
      && ["CANARY_EXFILTRATION", "HOST_ESCAPE_ATTEMPT", "DIGEST_MISMATCH"].includes(finding.code) && id(finding.code) === q.reasonCode);
    if (verdict !== "FAIL" || !reason || !Number.isSafeInteger(q.expiresAt) || q.expiresAt <= now || q.expiresAt > now + 86400 || q.deadline > q.expiresAt) fail();
    payload = { ...common, evidenceHash: evidence.reportRoot, reasonCode: id(reason.code), expiresAt: q.expiresAt };
  } else {
    const validFrom = Math.floor(Date.parse(scan.result.validFrom) / 1000), validUntil = Math.floor(Date.parse(scan.result.validUntil) / 1000);
    if (!Number.isSafeInteger(validFrom) || !Number.isSafeInteger(validUntil) || validFrom > now + 5 || validUntil <= now || validUntil <= validFrom
      || validUntil > validFrom + policy.validitySeconds || q.deadline > validUntil || template.verdict !== verdict) fail();
    payload = { ...common, artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest, toolSurfaceDigest: identity.toolSurfaceDigest,
      reportRoot: evidence.reportRoot, verdict: { PASS: 0, FAIL: 1, ABSTAIN: 2 }[verdict], validFrom, validUntil };
  }
  if (hash(payload) !== hash(q)) fail();
  return { domain, types, payload, verdict };
}

export async function runValidatorFanout(options: { apiUrl: string; token: string; scanId: string; privateKeys: string[]; quarantineFirst?: boolean;
  chainId: number; registryAddress: string; policyHash: string; rpcUrl: string }) {
  if (!Number.isSafeInteger(options.chainId) || options.chainId <= 0 || !/^0x[0-9a-fA-F]{40}$/.test(options.registryAddress)
    || !/^0x[0-9a-f]{64}$/.test(options.policyHash) || !/^[0-9a-f-]{36}$/.test(options.scanId)) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  const wallets = options.privateKeys.map((key) => new Wallet(key));
  if (wallets.length < 2 || wallets.length > 3 || new Set(wallets.map((wallet) => wallet.address)).size !== wallets.length) throw new Error("TWO_OR_THREE_UNIQUE_VALIDATORS_REQUIRED");
  const base = checkedServiceUrl(options.apiUrl), provider = new JsonRpcProvider(v2RpcRequest(options.rpcUrl), undefined, { batchMaxCount: 1 });
  const registry = createReleaseRegistryV2(options.registryAddress, provider);
  let scanTraceparent: string | undefined;
  const request = async (path: string, body?: any) => {
    const response = await boundedServiceRequest(new URL(path, base).href, { method: body ? "POST" : "GET",
      headers: { authorization: `Bearer ${options.token}`, "content-type": "application/json", ...traceHeaders() }, body: body ? JSON.stringify(body) : undefined });
    if (response.statusCode < 200 || response.statusCode >= 300) throw new Error(`VALIDATOR_API_HTTP_${response.statusCode}`);
    if (path === `/v1/scans/${options.scanId}` && !scanTraceparent) scanTraceparent = response.headers.traceparent;
    return JSON.parse(response.body.toString());
  };
  const settle = async (actionId: string, calldata: string) => {
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      const { action } = await request(`/v1/chain/actions/${actionId}`);
      if (action.status === "FAILED") throw new Error("CHAIN_ACTION_FAILED");
      if (action.status === "COMPLETED" && /^0x[0-9a-f]{64}$/.test(action.txHash ?? "")) {
        const [tx, receipt] = await Promise.all([provider.getTransaction(action.txHash), provider.getTransactionReceipt(action.txHash)]);
        if (tx?.to?.toLowerCase() !== options.registryAddress.toLowerCase() || tx.data !== calldata || tx.value !== 0n || receipt?.status !== 1) throw new Error("VALIDATOR_CHAIN_CONFIRMATION_MISMATCH");
        return action;
      }
      await setTimeout(500);
    }
    throw new Error("CHAIN_CONFIRMATION_TIMEOUT");
  };
  try {
    if ((await provider.getNetwork()).chainId !== BigInt(options.chainId)) throw new Error("CHAIN_ID_MISMATCH");
    await request(`/v1/scans/${options.scanId}`);
    return await withSpan("validator.fanout", { "mcpshield.scan_id": options.scanId, "mcpshield.chain_id": options.chainId }, async () => {
    const operations: Record<string, any>[] = [];
    for (let index = 0; index < 2; index++) {
      const wallet = wallets[index], { scan } = await request(`/v1/scans/${options.scanId}`), evidence = await request(`/v1/scans/${options.scanId}/evidence`);
      const policy = (await request("/v1/policies")).items.find((item: any) => item.policyHash === options.policyHash && !item.deprecatedAt)?.document;
      const validators = new Contract(await registry.validators(), ["function version() view returns(uint32)", "function isActiveValidator(address,uint32) view returns(bool)"], provider);
      const submit = async (quarantine = false) => withSpan("validator.attest", { "mcpshield.scan_id": options.scanId, "mcpshield.validator_id": wallet.address }, async () => {
        const version = Number(await validators.version());
        if (!await validators.isActiveValidator(wallet.address, version)) throw new Error("NOT_VALIDATOR");
        const template = await request(`/v1/scans/${options.scanId}/${quarantine ? "quarantine" : "attestation"}?validator=${wallet.address}`);
        const checked = await withSpan("validator.verify", { "mcpshield.scan_id": options.scanId }, async () => checkedValidatorPayload(template, { ...options, scan, evidence, policy, identity: await registry.releases(scan.releaseId),
          validatorSetVersion: version, nonce: Number(await registry.nonces(wallet.address)) }, quarantine));
        // Never sign server-supplied domain/types: only the pinned local definitions and reconstructed payload survive.
        const signature = await withSpan("validator.sign", { "mcpshield.validator_id": wallet.address }, () => wallet.signTypedData(checked.domain, checked.types, checked.payload));
        const { action } = await request(`/v1/validator/${quarantine ? "quarantines" : "attestations"}`, { scanId: options.scanId, payload: checked.payload, signature });
        operations.push(await settle(action.actionId, registry.interface.encodeFunctionData(quarantine ? "quarantineBySignature" : "submitAttestation", [checked.payload, signature])));
      });
      if (index === 0 && options.quarantineFirst && scan.result?.verdict === "FAIL") await submit(true);
      await submit();
    }
    return { mode: "SINGLE_INSTITUTION_DEMO", validators: wallets.slice(0, 2).map((wallet) => wallet.address), operations };
    }, { traceparent: scanTraceparent });
  } finally { provider.destroy(); }
}
async function main() {
  const privateKeys = JSON.parse(process.env.VALIDATOR_PRIVATE_KEYS ?? "[]");
  const { CONTROL_API_URL, CONTROL_API_TOKEN, CONTROL_SCAN_ID, CONTROL_V2_RPC_URLS, CONTROL_V2_CHAIN_ID, CONTROL_V2_REGISTRY_ADDRESS, CONTROL_VALIDATOR_POLICY_HASH } = process.env;
  if (!CONTROL_API_URL || !CONTROL_API_TOKEN || !CONTROL_SCAN_ID || !CONTROL_V2_RPC_URLS || !CONTROL_V2_CHAIN_ID || !CONTROL_V2_REGISTRY_ADDRESS || !CONTROL_VALIDATOR_POLICY_HASH) throw new Error("VALIDATOR_TRUST_CONFIG_REQUIRED");
  console.log(JSON.stringify(await runValidatorFanout({ apiUrl: CONTROL_API_URL, token: CONTROL_API_TOKEN, scanId: CONTROL_SCAN_ID, privateKeys,
    chainId: Number(CONTROL_V2_CHAIN_ID), registryAddress: CONTROL_V2_REGISTRY_ADDRESS, policyHash: CONTROL_VALIDATOR_POLICY_HASH,
    rpcUrl: CONTROL_V2_RPC_URLS.split(",")[0], quarantineFirst: process.argv.includes("--quarantine") })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(() => { console.error("VALIDATOR_OPERATION_FAILED"); process.exitCode = 1; });
