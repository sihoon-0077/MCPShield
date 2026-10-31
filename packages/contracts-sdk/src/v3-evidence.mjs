import { createHash } from "node:crypto";

// ADR-008 off-chain half of a V3 vote: the evidence file whose sha256 a validator signs as evidenceHash.
// Shared by the validator that writes it and by anyone (operator API, dashboard, auditor) that checks it.
export const VERDICTS = ["PASS", "FAIL", "ABSTAIN"];
export const QUARANTINE_REASONS = ["CANARY_EXFILTRATION", "HOST_ESCAPE_ATTEMPT", "DIGEST_MISMATCH"];
export const EVIDENCE_SCHEMA = "mcpshield.validator-evidence.v3";
export const MAX_EVIDENCE_BYTES = 128 * 1024;

/**
 * ADR-002 on a set of findings. A deterministic non-AI HIGH/CRITICAL finding is FAIL. Otherwise any
 * non-deterministic HIGH/CRITICAL finding (an AI suspicion) or an incomplete scan is ABSTAIN: AI is a
 * witness that can hold a release for review, never the judge that revokes it. Everything else is PASS.
 */
export function verdictFromFindings(findings, complete = true) {
  const codes = (list) => [...new Set(list.map((f) => f.code))];
  const blocking = (f) => ["HIGH", "CRITICAL"].includes(f.severity);
  const hard = findings.filter((f) => f.deterministic === true && f.stage !== "AI" && blocking(f));
  if (hard.length) return { verdict: "FAIL", basis: codes(hard) };
  const suspicion = findings.filter((f) => (f.stage === "AI" || f.deterministic !== true) && blocking(f));
  if (suspicion.length || !complete) return { verdict: "ABSTAIN", basis: codes(suspicion.length ? suspicion : findings) };
  return { verdict: "PASS", basis: [] };
}

export function verdictFromReport(report) {
  if (!Array.isArray(report?.findings) || !["PASSED", "FAILED"].includes(report?.scanStatus)) return { verdict: "ABSTAIN", basis: ["SCAN_INCOMPLETE"] };
  const result = verdictFromFindings(report.findings, true);
  // A scanner that calls its own result FAILED without a FAIL-grade finding is inconsistent, so never PASS it.
  return report.scanStatus === "FAILED" && result.verdict === "PASS" ? { verdict: "ABSTAIN", basis: ["SCAN_STATUS_INCONSISTENT"] } : result;
}

/** The deterministic sandbox finding that allows a one-validator emergency quarantine, if any. */
export function quarantineReason(report) {
  const finding = (report?.findings ?? []).find((f) => f.deterministic === true && f.stage !== "AI" && f.severity === "CRITICAL"
    && QUARANTINE_REASONS.includes(f.code));
  return finding ? finding.code : null;
}

/** Evidence = this validator's own report bound to its address and the on-chain identity; the hash covers the exact bytes written. */
export function evidenceDocument(validator, release, report, verdict) {
  const file = `${JSON.stringify({ schema: EVIDENCE_SCHEMA, validator, release, verdict: verdict.verdict, basis: verdict.basis, report }, null, 2)}\n`;
  return { file, evidenceHash: `0x${createHash("sha256").update(file).digest("hex")}` };
}

const sameRelease = (a, b) => ["releaseId", "artifactDigest", "manifestDigest", "toolSurfaceDigest"].every((key) => typeof a?.[key] === "string" && a[key] === b[key]);

/**
 * Checks an evidence file against the vote it backs: exact bytes (sha256 = evidenceHash), the signer and the on-chain
 * identity. `consistent` says whether the signed verdict is what ADR-002 derives from the file's own report; a mismatch
 * is published, not refused, so an operator cannot use this check to drop a dissenting vote.
 */
export function checkedVoteEvidence(file, { evidenceHash, validator, release, verdict }) {
  if (typeof file !== "string" || Buffer.byteLength(file) > MAX_EVIDENCE_BYTES) throw new Error("VALIDATOR_EVIDENCE_INVALID");
  if (`0x${createHash("sha256").update(file).digest("hex")}` !== evidenceHash) throw new Error("VALIDATOR_EVIDENCE_HASH_MISMATCH");
  let document;
  try { document = JSON.parse(file); } catch { throw new Error("VALIDATOR_EVIDENCE_INVALID"); }
  if (document?.schema !== EVIDENCE_SCHEMA || typeof document.validator !== "string" || document.validator.toLowerCase() !== validator.toLowerCase()
    || !sameRelease(document.release, release) || !VERDICTS.includes(document.verdict) || !Array.isArray(document.basis)) throw new Error("VALIDATOR_EVIDENCE_BINDING_MISMATCH");
  const derived = verdictFromReport(document.report);
  return { document, derived, consistent: derived.verdict === document.verdict && (verdict === undefined || VERDICTS[verdict] === document.verdict) };
}
