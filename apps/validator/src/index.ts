import { Wallet } from "ethers";
import {
  attestationDomain,
  attestationTypes,
  chainDecisions,
  releaseKey,
} from "../../../packages/contracts-sdk/src/index.js";
import { SCHEMA_VERSION, type ValidatorDecision } from "../../../packages/protocol/api/types.js";

const required = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`Set ${name}`);
  return value;
};

const apiUrl = process.env.API_URL ?? "http://127.0.0.1:3001";
const privateKey = required("VALIDATOR_PRIVATE_KEY");
const releaseId = required("RELEASE_ID");
const scanId = required("SCAN_ID");
const decision = required("DECISION") as ValidatorDecision;
const evidenceHash = required("EVIDENCE_HASH");
const chainId = Number(required("ATTESTATION_CHAIN_ID"));
const verifyingContract = required("ATTESTATION_CONTRACT");
const nonce = Number(required("NONCE"));
const deadline = Number(process.env.DEADLINE ?? Math.floor(Date.now() / 1000) + 300);
if (!chainDecisions.hasOwnProperty(decision) || !Number.isSafeInteger(nonce)) {
  throw new Error("Invalid DECISION or NONCE");
}

const signer = new Wallet(privateKey);
const signature = await signer.signTypedData(
  attestationDomain(chainId, verifyingContract),
  attestationTypes,
  { releaseKey: releaseKey(releaseId), decision: chainDecisions[decision], evidenceHash, nonce, deadline },
);

const response = await fetch(`${apiUrl}/api/validators/vote`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ schemaVersion: SCHEMA_VERSION, releaseId, scanId, decision, evidenceHash, nonce, deadline, signature }),
  signal: AbortSignal.timeout(Number(process.env.API_TIMEOUT_MS ?? 5_000)),
});
console.log(await response.text());
if (!response.ok) process.exitCode = 1;
