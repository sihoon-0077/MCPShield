export const validReceiptWriter = (value: unknown): value is string => typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value) && !/^0x0{40}$/.test(value);

export type ReceiptEvidenceSummary = { verification: "API_VERIFIED"; root: string; leafCount: number; checkedAt: string };

// The authenticated API decrypts and verifies the bundle. Only its verification summary crosses the BFF.
export function receiptEvidenceSummary(payload: unknown): ReceiptEvidenceSummary {
  const manifest = (payload as { bundle?: { manifest?: { algorithm?: string; root?: string; leaves?: unknown[] } } })?.bundle?.manifest;
  if (!manifest || manifest.algorithm !== "sha256-path-merkle-v1" || typeof manifest.root !== "string" || !/^0x[a-f0-9]{64}$/.test(manifest.root) || !Array.isArray(manifest.leaves) || manifest.leaves.length < 2 || manifest.leaves.length > 128) throw new Error("RECEIPT_EVIDENCE_INVALID");
  return { verification: "API_VERIFIED", root: manifest.root, leafCount: manifest.leaves.length, checkedAt: new Date().toISOString() };
}
