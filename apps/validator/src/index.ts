import { SCHEMA_VERSION } from "../../../packages/protocol/api/types.js";

const apiUrl = process.env.API_URL ?? "http://127.0.0.1:3001";
const validatorAddress = process.env.VALIDATOR_ADDRESS;
const releaseId = process.env.RELEASE_ID;
const decision = process.env.DECISION;
const evidenceHash = process.env.EVIDENCE_HASH;

if (!validatorAddress || !releaseId || !decision || !evidenceHash) {
  throw new Error(
    "Set VALIDATOR_ADDRESS, RELEASE_ID, DECISION and EVIDENCE_HASH",
  );
}

const response = await fetch(`${apiUrl}/api/validators/vote`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    schemaVersion: SCHEMA_VERSION,
    validatorAddress,
    releaseId,
    decision,
    evidenceHash,
  }),
});
const body = await response.text();
console.log(body);
if (!response.ok) process.exitCode = 1;
