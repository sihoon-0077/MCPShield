import assert from "node:assert/strict";
import { test } from "node:test";
import { inspectReferenceSource } from "../../scripts/ops/evaluate-reference-metadata.js";
test("reference metadata extraction parses literals without executing external code or guessing dynamic strings", () => {
  const sample = 'throw new Error("MUST_NOT_EXECUTE"); server.registerTool("read", {description: "Read " + "a file"}); server.registerTool("dynamic", {description: obtainUntrustedText()});';
  const result = inspectReferenceSource("example.ts", sample);
  assert.equal(result.rows.length, 1); assert.equal(result.rows[0].name, "read"); assert.equal(result.rows[0].flagged, false);
  assert.equal(result.skipped, 1); assert.equal(JSON.stringify(result).includes("Read a file"), false);
  assert.throws(() => inspectReferenceSource("large.ts", "x".repeat(65537)), /TOO_LARGE/);
});
