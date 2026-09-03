import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { buildApp } from "../../apps/api/src/app.js";

const validators = [
  "0x0000000000000000000000000000000000000001",
  "0x0000000000000000000000000000000000000002",
  "0x0000000000000000000000000000000000000003",
];
const digestA = `sha256:${"a".repeat(64)}`;
const toolHash = `0x${"b".repeat(64)}`;
const evidenceHash = `0x${"c".repeat(64)}`;

async function register(app: Awaited<ReturnType<typeof buildApp>>, releaseId: string) {
  return app.inject({
    method: "POST",
    url: "/api/releases",
    payload: {
      schemaVersion: "1.0.0",
      releaseId,
      artifactDigest: digestA,
      toolSurfaceHash: toolHash,
    },
  });
}

async function vote(
  app: Awaited<ReturnType<typeof buildApp>>,
  releaseId: string,
  validatorAddress: string,
  decision: "PASS" | "FAIL" | "ABSTAIN",
) {
  return app.inject({
    method: "POST",
    url: "/api/validators/vote",
    payload: {
      schemaVersion: "1.0.0",
      releaseId,
      validatorAddress,
      decision,
      evidenceHash,
    },
  });
}

test("stores canonical scan results and rejects unknown fields", async (t) => {
  const app = await buildApp({ databasePath: ":memory:", validatorAddresses: validators });
  t.after(() => app.close());
  assert.equal((await register(app, "mail-mcp@1.0.0")).statusCode, 201);

  const scan = {
    schemaVersion: "1.0.0",
    scanId: randomUUID(),
    releaseId: "mail-mcp@1.0.0",
    artifactDigest: digestA,
    toolSurfaceHash: toolHash,
    scanStatus: "PASSED",
    findings: [],
    evidenceHash,
    source: "LIVE",
  };
  const stored = await app.inject({ method: "POST", url: "/api/scans", payload: scan });
  assert.equal(stored.statusCode, 201);

  const fetched = await app.inject({ method: "GET", url: `/api/scans/${scan.scanId}` });
  assert.deepEqual(fetched.json(), scan);

  const invalid = await app.inject({
    method: "POST",
    url: "/api/scans",
    payload: { ...scan, scanId: randomUUID(), internalSecret: "must-not-pass" },
  });
  assert.equal(invalid.statusCode, 400);
  assert.equal(invalid.json().error.code, "INVALID_SCAN_RESULT");
});

test("two PASS votes verify and admission allows only the matching digest", async (t) => {
  const app = await buildApp({ databasePath: ":memory:", validatorAddresses: validators });
  t.after(() => app.close());
  await register(app, "mail-mcp@1.0.0");

  assert.equal((await vote(app, "mail-mcp@1.0.0", validators[0], "PASS")).statusCode, 201);
  const second = await vote(app, "mail-mcp@1.0.0", validators[1], "PASS");
  assert.equal(second.json().release.status, "VERIFIED");

  const allowed = await app.inject({
    method: "POST",
    url: "/api/admission/check",
    payload: { schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.0", artifactDigest: digestA },
  });
  assert.equal(allowed.json().decision, "ALLOW");
  assert.equal(allowed.json().reasonCode, "RELEASE_VERIFIED");

  const mismatch = await app.inject({
    method: "POST",
    url: "/api/admission/check",
    payload: {
      schemaVersion: "1.0.0",
      releaseId: "mail-mcp@1.0.0",
      artifactDigest: `sha256:${"d".repeat(64)}`,
    },
  });
  assert.equal(mismatch.json().decision, "BLOCK");
  assert.equal(mismatch.json().reasonCode, "DIGEST_MISMATCH");
});

test("rejects outsiders and duplicate votes; two FAIL votes revoke", async (t) => {
  const app = await buildApp({ databasePath: ":memory:", validatorAddresses: validators });
  t.after(() => app.close());
  await register(app, "mail-mcp@1.0.1");

  const outsider = await vote(
    app,
    "mail-mcp@1.0.1",
    "0x0000000000000000000000000000000000000009",
    "FAIL",
  );
  assert.equal(outsider.statusCode, 403);

  const first = await vote(app, "mail-mcp@1.0.1", validators[0], "FAIL");
  assert.equal(first.json().release.status, "QUARANTINED");
  const duplicate = await vote(app, "mail-mcp@1.0.1", validators[0], "FAIL");
  assert.equal(duplicate.statusCode, 409);
  assert.equal(duplicate.json().error.code, "DUPLICATE_VOTE");

  const second = await vote(app, "mail-mcp@1.0.1", validators[1], "FAIL");
  assert.equal(second.json().release.status, "REVOKED");

  const admission = await app.inject({
    method: "POST",
    url: "/api/admission/check",
    payload: { schemaVersion: "1.0.0", releaseId: "mail-mcp@1.0.1", artifactDigest: digestA },
  });
  assert.equal(admission.json().decision, "BLOCK");
  assert.equal(admission.json().reasonCode, "RELEASE_REVOKED");

  const events = await app.inject({
    method: "GET",
    url: "/api/events?releaseId=mail-mcp%401.0.1",
  });
  assert.deepEqual(
    events.json().events.filter((entry: { eventName: string }) => entry.eventName === "StatusChanged")
      .map((entry: { status: string }) => entry.status),
    ["QUARANTINED", "REVOKED"],
  );
});
