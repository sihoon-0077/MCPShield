import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

test("actual local EVM fullcycle exports connected scan/validator/chain/indexer/admission OTLP (loopback contract collector)", { timeout: 150000 }, async (t) => {
  // This bounded JSON receiver tests the real HTTP exporter contract. It is not a production OTel Collector,
  // storage/query backend, or proof of real Docker scanning (the existing Linux Docker gate covers that).
  // Portable report-fixture signing spans are emitted explicitly in test code, not a production signer bypass.
  const deliveries: { path: string; body: any }[] = [];
  let totalBytes = 0, collectorFailure: Error | undefined;
  const server = createServer({ requestTimeout: 5000, headersTimeout: 3000 }, async (request, reply) => {
    try {
      assert.equal(request.method, "POST");
      assert.ok(["/v1/traces", "/v1/metrics"].includes(request.url ?? ""));
      assert.ok(deliveries.length < 200);
      let size = 0; const chunks: Buffer[] = [];
      for await (const chunk of request) {
        size += chunk.length; totalBytes += chunk.length;
        assert.ok(size <= 2 * 1024 * 1024 && totalBytes <= 16 * 1024 * 1024, "OTLP receiver byte limit exceeded");
        chunks.push(Buffer.from(chunk));
      }
      deliveries.push({ path: request.url!, body: JSON.parse(Buffer.concat(chunks).toString()) });
      reply.writeHead(200, { "content-type": "application/json" }).end("{}");
    } catch (error) { collectorFailure = error as Error; reply.writeHead(400).end(); }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  const endpoint = `http://127.0.0.1:${address.port}`;
  try {
    const environment = { ...process.env };
    // A new test runner must not inherit its parent's internal binary IPC/reporting mode.
    delete environment.NODE_TEST_CONTEXT;
    const child = await promisify(execFile)(process.execPath, ["--import", "tsx", "--test", "--test-name-pattern=report fixture",
      fileURLToPath(new URL("../api/v2-fullcycle.test.ts", import.meta.url))], {
      cwd: fileURLToPath(new URL("../../", import.meta.url)), windowsHide: true, timeout: 120000, maxBuffer: 1024 * 1024,
      env: { ...environment, MCPSHIELD_FULLCYCLE_OTLP_TEST: "1", MCPSHIELD_TELEMETRY_ENABLED: "true", MCPSHIELD_DOCKER_TESTS: "0",
        OTEL_SERVICE_NAME: "mcpshield-fullcycle-contract-test", OTEL_TRACES_SAMPLER: "always_on", OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
        OTEL_EXPORTER_OTLP_HEADERS: "", OTEL_EXPORTER_OTLP_TRACES_HEADERS: "", OTEL_EXPORTER_OTLP_METRICS_HEADERS: "",
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: `${endpoint}/v1/traces`, OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: `${endpoint}/v1/metrics` },
    });
    assert.match(child.stdout, /V2 genuine EVM/);
    assert.equal(collectorFailure, undefined);
    assert.ok(deliveries.some((item) => item.path === "/v1/metrics"), "shutdown must flush metrics too");
    const spans: any[] = deliveries.filter((item) => item.path === "/v1/traces").flatMap((item) => item.body.resourceSpans.flatMap((resource: any) =>
      resource.scopeSpans.flatMap((scope: any) => scope.spans)));
    const fanout = spans.find((span) => span.name === "validator.fanout"); assert.ok(fanout, "fixture signing trace contract was not exported");
    const selected = spans.filter((span) => span.traceId === fanout.traceId), byId = new Map(selected.map((span) => [span.spanId, span]));
    const required = ["scan.accept", "scan.execute", "scan.read", "validator.fanout", "validator.attest", "validator.verify", "validator.sign", "validator.accept", "chain.submit", "indexer.observe", "admission.decision"];
    for (const name of required) assert.ok(selected.some((span) => span.name === name), `missing ${name} under the authoritative scan trace`);
    const parentName = (span: any) => byId.get(span.parentSpanId)?.name;
    const parentContracts: Record<string, string> = { "scan.execute": "scan.accept", "scan.read": "scan.accept", "validator.fanout": "scan.read",
      "validator.attest": "validator.fanout", "validator.verify": "validator.attest", "validator.sign": "validator.attest", "validator.accept": "validator.attest",
      "chain.submit": "validator.accept", "indexer.observe": "chain.submit", "admission.decision": "scan.accept" };
    for (const span of selected.filter((span) => parentContracts[span.name])) assert.equal(parentName(span), parentContracts[span.name], `broken parent for ${span.name}`);
    assert.equal(selected.filter((span) => span.name === "scan.accept").length, 1);
    assert.ok(selected.filter((span) => span.name === "validator.sign").length >= 2);
    const root = selected.find((span) => span.name === "scan.accept")!;
    for (const span of selected) {
      let cursor = span; const visited = new Set();
      while (cursor.spanId !== root.spanId) {
        assert.equal(visited.has(cursor.spanId), false, "trace parent cycle"); visited.add(cursor.spanId);
        cursor = byId.get(cursor.parentSpanId); assert.ok(cursor, `orphan exported parent for ${span.name}`);
      }
    }
    // The Gateway request can have a foreign trace; only the evidence-linked decision is reparented.
    const foreign = spans.filter((span) => span.traceId === "f".repeat(32));
    assert.ok(foreign.some((span) => span.name === "admission.check"));
    assert.equal(foreign.some((span) => required.includes(span.name)), false);
    assert.notEqual(fanout.traceId, "f".repeat(32));
    const encoded = JSON.stringify(deliveries);
    assert.doesNotMatch(encoded, /synthetic-v2-test-admin-token|synthetic-trace-poison|Synthetic report fixture|list_messages|Welcome|BEGIN PRIVATE KEY|privateKeys|authorization|baggage|exception\.(?:message|stacktrace)|"signature"|"raw_tx"|"payload"/i);
    const allowed = new Set(["mcpshield.scan_id", "mcpshield.release_id", "mcpshield.policy_hash_prefix", "mcpshield.artifact_digest_prefix", "mcpshield.stage", "mcpshield.finding_code",
      "mcpshield.verdict", "mcpshield.validator_id", "mcpshield.chain_id", "mcpshield.block_number", "mcpshield.gateway_decision", "mcpshield.source"]);
    for (const span of spans) for (const attribute of span.attributes ?? []) assert.ok(allowed.has(attribute.key), `unapproved exported span attribute ${attribute.key}`);
    t.diagnostic(JSON.stringify({ mode: "LOCAL_EVM_REPORT_FIXTURE_REAL_OTLP_HTTP", validatorExecution: "EXPLICIT_TEST_ONLY_SIGNING", spans: spans.length, connectedScanSpans: selected.length,
      traceRequests: deliveries.filter((item) => item.path === "/v1/traces").length, bytes: totalBytes }));
  } finally { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
});
