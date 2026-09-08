import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import ts from "typescript";
// @ts-expect-error Shared scanner is native ESM.
import { metadataSignals } from "../../services/scanner/src/analysis.mjs";

export const referenceSource = {
  repository: "https://github.com/modelcontextprotocol/servers", commit: "d73f99efbfd40c3aa1b61e88728b3d49fb52608f",
  licenseUrl: "https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/LICENSE",
  licenseNote: "Upstream describes an MIT to Apache-2.0 transition; documentation CC-BY-4.0. Raw sources/descriptions are not redistributed.",
  files: {
    "src/filesystem/index.ts": "bff21de612c59d64b351f70615f44563f0efe76666a75aa52450ebe6fae6584a",
    "src/memory/index.ts": "fa1d38913ecdfca22231dbcf3b047548417f2ca862ef42de69394883223c32b6",
    "src/sequentialthinking/index.ts": "fab7b6e9817d67fe83fdc4f4b1d18bb3a2c034cbd8066b0ec84d85679d13c22c",
  },
};
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
function literal(node: ts.Node | undefined, depth = 0): string | undefined {
  if (!node || depth > 128) return;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = literal(node.left, depth + 1), right = literal(node.right, depth + 1);
    if (left !== undefined && right !== undefined) return left + right;
  }
}
// Parse, never import/eval/transpile/execute external server code. Dynamic strings
// and indirect registrations are excluded and counted instead of guessed.
export function inspectReferenceSource(filename: string, source: string) {
  if (Buffer.byteLength(source) > 65536) throw Error("REFERENCE_SOURCE_TOO_LARGE");
  const ast = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true);
  const rows: Array<{ name: string; descriptionHash: string; flagged: boolean }> = []; let skipped = 0;
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "registerTool") {
      const name = literal(node.arguments[0]), config = node.arguments[1];
      const property = config && ts.isObjectLiteralExpression(config) ? config.properties.find((item) => ts.isPropertyAssignment(item) && item.name.getText(ast) === "description") : undefined;
      const description = property && ts.isPropertyAssignment(property) ? literal(property.initializer) : undefined;
      if (name !== undefined && description !== undefined) rows.push({ name, descriptionHash: sha(description), flagged: metadataSignals([{ name, description }]).length > 0 });
      else skipped++;
    }
    ts.forEachChild(node, visit);
  };
  visit(ast); return { path: filename, sha256: sha(source), skipped, rows };
}
export async function measureReferenceMetadata() {
  const sources = [];
  for (const [path, expectedHash] of Object.entries(referenceSource.files)) {
    const response = await fetch(`https://raw.githubusercontent.com/modelcontextprotocol/servers/${referenceSource.commit}/${path}`, { redirect: "error", signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw Error("REFERENCE_SOURCE_UNAVAILABLE");
    const reader = response.body!.getReader(), chunks = []; let size = 0;
    try {
      while (true) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > 65536) throw Error("REFERENCE_SOURCE_TOO_LARGE"); chunks.push(Buffer.from(value)); }
    } finally { await reader.cancel(); }
    const source = Buffer.concat(chunks).toString("utf8"); if (sha(source) !== expectedHash) throw Error("REFERENCE_SOURCE_HASH_MISMATCH");
    sources.push(inspectReferenceSource(path, source));
  }
  const rows = sources.flatMap((source) => source.rows), flagged = rows.filter((row) => row.flagged).length;
  if (!rows.length) throw Error("REFERENCE_SAMPLE_EMPTY");
  return { status: "MEASURED", measuredAt: new Date().toISOString(), source: referenceSource, method: "STATIC_AST_LITERAL_NAMES_AND_DESCRIPTIONS_ONLY",
    labelBasis: "REFERENCE_TOOL_NOT_INDEPENDENTLY_LABELED", sampleSize: rows.length, flagged, reviewRate: flagged / rows.length,
    falsePositiveRate: null, runtimeSafetyVerified: false, sources,
    limitations: ["Reference implementations are not a security certification or independent benign labeling.", "Input schemas, dynamic metadata and runtime behavior are not evaluated.", "Small convenience sample; do not generalize its review rate to all MCP tools.", "No upstream code was executed or raw descriptions redistributed."] };
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const result = await measureReferenceMetadata();
  const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", windowsHide: true }).trim();
  const worktreeDirty = Boolean(execFileSync("git", ["status", "--porcelain"], { encoding: "utf8", windowsHide: true }).trim());
  console.log(JSON.stringify({ ...result, sourceCommit, worktreeDirty }, null, 2));
}
