import { Wallet } from "ethers";
import { pathToFileURL } from "node:url";
import { setTimeout } from "node:timers/promises";
import { policyVerdict } from "../../api/src/control-policy.js";
// @ts-expect-error Scanner evidence is shared ESM JavaScript.
import { verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";

export async function runValidatorFanout(options: { apiUrl: string; token: string; scanId: string; privateKeys: string[]; quarantineFirst?: boolean }) {
  const wallets = options.privateKeys.map((key) => new Wallet(key));
  if (wallets.length < 2 || wallets.length > 3 || new Set(wallets.map((wallet) => wallet.address)).size !== wallets.length) throw new Error("TWO_OR_THREE_UNIQUE_VALIDATORS_REQUIRED");
  const base = new URL(options.apiUrl);
  if (base.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname)) throw new Error("HTTPS_REQUIRED");
  const request = async (path: string, body?: any) => {
    const response = await fetch(new URL(path, base), { method: body ? "POST" : "GET", redirect: "error", signal: AbortSignal.timeout(5000),
      headers: { authorization: `Bearer ${options.token}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    if (!response.ok) throw new Error(`VALIDATOR_API_HTTP_${response.status}`); return response.json();
  };
  const settle = async (actionId: string) => {
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      const { action } = await request(`/v1/chain/actions/${actionId}`);
      if (action.status === "COMPLETED") return action;
      if (action.status === "FAILED") throw new Error(action.errorCode ?? "CHAIN_ACTION_FAILED");
      await setTimeout(500);
    }
    throw new Error("CHAIN_CONFIRMATION_TIMEOUT");
  };
  const operations = [];
  for (let index = 0; index < 2; index++) {
    const wallet = wallets[index];
    const evidence = await request(`/v1/scans/${options.scanId}/evidence`);
    if (!verifyEvidenceBundle(evidence.bundle, evidence.reportRoot)) throw new Error("EVIDENCE_INTEGRITY_MISMATCH");
    const report = JSON.parse(evidence.bundle.files["report.json"]);
    const verdict = policyVerdict(evidence.bundle, report);
    if (index === 0 && options.quarantineFirst && verdict === "FAIL") {
      const template = await request(`/v1/scans/${options.scanId}/quarantine?validator=${wallet.address}`);
      if (template.payload.evidenceHash !== evidence.reportRoot) throw new Error("REPORT_ROOT_MISMATCH");
      const signature = await wallet.signTypedData(template.domain, template.types, template.payload);
      const { action } = await request("/v1/validator/quarantines", { scanId: options.scanId, payload: template.payload, signature });
      operations.push(await settle(action.actionId));
    }
    const template = await request(`/v1/scans/${options.scanId}/attestation?validator=${wallet.address}`);
    if (template.payload.reportRoot !== evidence.reportRoot || template.verdict !== verdict) throw new Error("VALIDATOR_VERDICT_MISMATCH");
    const signature = await wallet.signTypedData(template.domain, template.types, template.payload);
    const { action } = await request("/v1/validator/attestations", { scanId: options.scanId, payload: template.payload, signature });
    operations.push(await settle(action.actionId));
  }
  return { mode: "SINGLE_INSTITUTION_DEMO", validators: wallets.slice(0, 2).map((wallet) => wallet.address), operations };
}
async function main() {
  const privateKeys = JSON.parse(process.env.VALIDATOR_PRIVATE_KEYS ?? "[]");
  const { CONTROL_API_URL, CONTROL_API_TOKEN, CONTROL_SCAN_ID } = process.env;
  if (!CONTROL_API_URL || !CONTROL_API_TOKEN || !CONTROL_SCAN_ID) throw new Error("CONTROL_API_URL_TOKEN_SCAN_ID_REQUIRED");
  console.log(JSON.stringify(await runValidatorFanout({ apiUrl: CONTROL_API_URL, token: CONTROL_API_TOKEN, scanId: CONTROL_SCAN_ID, privateKeys, quarantineFirst: process.argv.includes("--quarantine") })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
