export type V3Verdict = "PASS" | "FAIL" | "ABSTAIN";
export type V3Release = { releaseId: string; artifactDigest: string; manifestDigest: string; toolSurfaceDigest: string };
export declare const VERDICTS: readonly V3Verdict[];
export declare const QUARANTINE_REASONS: readonly string[];
export declare const EVIDENCE_SCHEMA: string;
export declare const MAX_EVIDENCE_BYTES: number;
export declare function verdictFromFindings(findings: any[], complete?: boolean): { verdict: V3Verdict; basis: string[] };
export type V3AiWitness = { required: true; provider: string; model: string | null; status: "COMPLETED" | "UNAVAILABLE"; error?: string };
export declare const AI_WITNESS_STATUSES: readonly V3AiWitness["status"][];
export declare function verdictFromReport(report: any, ai?: V3AiWitness): { verdict: V3Verdict; basis: string[] };
export declare function quarantineReason(report: any): string | null;
export declare function evidenceDocument(validator: string, release: V3Release, report: any, verdict: { verdict: V3Verdict; basis: string[] }, ai?: V3AiWitness): { file: string; evidenceHash: string };
export declare function checkedVoteEvidence(file: unknown, expected: { evidenceHash: string; validator: string; release: V3Release; verdict?: number }):
  { document: any; derived: { verdict: V3Verdict; basis: string[] }; consistent: boolean };
