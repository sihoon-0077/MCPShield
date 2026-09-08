import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { promisify } from "node:util";
import * as tar from "tar";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { importOciRuntime } from "../../../services/resolver/src/oci-runtime.mjs";
import { ociHash, OCI_SOURCE_BUDGET_PROFILE } from "../../../services/resolver/src/oci-runtime-descriptor.mjs";
import { artifactDigest } from "../../../services/scanner/src/scanner.mjs";
import { canonicalJson } from "../../../services/scanner/src/evidence.mjs";
import { observeOciRuntime } from "../../../services/scanner/src/oci-observer.mjs";
import { createOciReleaseBinding, ociExecutionPolicy } from "../../../services/scanner/src/oci-binding.mjs";
import { removeFixtureSnapshot } from "../../../services/scanner/src/snapshot.mjs";
import { AdmissionBlockedError, runArtifact } from "../src/index.mjs";

const execute = promisify(execFile);
const tools = ["first", "second"].map(name => ({ name, inputSchema: { type: "object", properties: { linger: { type: "boolean" } }, additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false } }));
const modern = message => ({ jsonrpc: "2.0", ...message, params: { ...message.params, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": { name: "synthetic-oci-gateway", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} } } });
const wire = (...messages) => messages.map(modern).map(JSON.stringify).join("\n") + "\n";
const call = (name = "second", args = {}) => ({ id: 3, method: "tools/call", params: { name, arguments: args } });
async function docker(args, { binary = false, timeout = 10000 } = {}) {
  try { const result = await execute("docker", args, { timeout, maxBuffer: 32 * 1024 * 1024, encoding: binary ? "buffer" : "utf8", windowsHide: true }); return binary ? result.stdout : result.stdout.trim(); }
  catch { throw Error("SYNTHETIC_OCI_DOCKER_COMMAND_FAILED"); }
}
const ownedContainers = async () => (await docker(["container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "label=io.mcpshield.gateway.owner"])).split("\n").filter(Boolean).sort();

// A native shell fixture assembled ONLY from the operator-pinned local builder.
// Full runtime/transport exercise, but the approval issuer/7 review anchors are
// explicitly synthetic: this test is not an independent scan/quorum claim.
test("actual OCI native shell → source import/observation → signed Gateway enforces isolation and per-call revocation", {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1" || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE, timeout: 300000,
}, async () => {
  assert.equal(process.platform, "linux");
  const builder = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE; assert.match(builder, /^sha256:[a-f0-9]{64}$/);
  const root = await mkdtemp(join(tmpdir(), "mcpshield-oci-gateway-native-")), build = join(root, "build"), source = join(root, "source");
  const tag = `mcpshield-oci-gateway-test-${randomUUID()}:local`, before = await ownedContainers();
  let imported, server, built = false;
  try {
    await mkdir(build); await mkdir(source);
    await writeFile(join(build, "Dockerfile"), [`FROM ${builder} AS approved`, "FROM scratch",
      "COPY --from=approved /bin/busybox /bin/busybox", "COPY --from=approved /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1",
      "COPY --chmod=0555 server.sh /server.sh", "ENV PATH=/bin", "USER 1000:1000", 'ENTRYPOINT ["/bin/busybox"]', 'CMD ["sh","/server.sh"]'].join("\n"));
    await writeFile(join(build, "server.sh"), ["#!/bin/busybox sh", "linger=0", "while IFS= read -r line; do",
      `id=$(printf '%s' "$line" | /bin/busybox sed -n 's/.*"id":\\([^,}]*\\).*/\\1/p')`, '[ -n "$id" ] || continue', 'case "$line" in',
      `*'"initialize"'*) result='{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"synthetic-oci-native","version":"1"}}' ;;`,
      `*'"tools/list"'*) case "$line" in *'"cursor":"second"'*) result='${JSON.stringify({ tools: [tools[1]] })}' ;; *) result='${JSON.stringify({ tools: [tools[0]], nextCursor: "second" })}' ;; esac ;;`,
      `*'"tools/call"'*) text=SYNTHETIC_OBSERVATION_ONLY`,
      'if [ "$HOME" = /nonexistent ]; then', 'text=SYNTHETIC_NATIVE_ISOLATION_OK',
      '[ "$(/bin/busybox id -u)" = 1000 ] || text=SYNTHETIC_NATIVE_ISOLATION_FAILED',
      '[ "$(/bin/busybox ls /sys/class/net)" = lo ] || text=SYNTHETIC_NATIVE_ISOLATION_FAILED',
      '[ "$PYTHONDONTWRITEBYTECODE" = 1 ] && [ -z "${MCPSHIELD_CONTROL_TOKEN+x}" ] || text=SYNTHETIC_NATIVE_ISOLATION_FAILED',
      '/bin/busybox grep -q "^CapEff:[[:space:]]*0000000000000000$" /proc/self/status || text=SYNTHETIC_NATIVE_ISOLATION_FAILED',
      '/bin/busybox grep -q "^NoNewPrivs:[[:space:]]*1$" /proc/self/status || text=SYNTHETIC_NATIVE_ISOLATION_FAILED',
      '/bin/busybox grep -q "^Seccomp:[[:space:]]*2$" /proc/self/status || text=SYNTHETIC_NATIVE_ISOLATION_FAILED',
      'if ( : > /must-not-write ) 2>/dev/null; then text=SYNTHETIC_NATIVE_ISOLATION_FAILED; fi', 'fi',
      `result='{"content":[{"type":"text","text":"'"$text"'"}]}'`, `case "$line" in *'"linger":true'*) linger=1 ;; esac ;;`,
      `*) result='{}' ;;`, 'esac', `printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$result"`,
      'echo SYNTHETIC_CANDIDATE_STDERR_PRIVATE >&2', 'done', '[ "$linger" = 0 ] || exec /bin/busybox sleep 3600',
    ].join("\n"));
    await docker(["build", "--network=none", "--pull=false", "--tag", tag, build], { timeout: 60000 }); built = true;
    const image = JSON.parse(await docker(["image", "inspect", tag, "--format", "{{json .}}"]));
    // Convert only Docker's locally produced archive into the Resolver's OCI layout.
    const archive = await docker(["image", "save", tag], { binary: true }), entries = new Map();
    const parser = tar.t({ sync: true, strict: true, onReadEntry(entry) {
      const chunks = []; entry.on("data", chunk => chunks.push(chunk)); entry.on("end", () => entries.set(entry.path, Buffer.concat(chunks)));
    } }); parser.end(archive);
    const saved = JSON.parse(entries.get("manifest.json").toString()); assert.equal(saved.length, 1);
    const configBytes = entries.get(saved[0].Config), layers = saved[0].Layers.map(path => entries.get(path)); assert.equal(ociHash(configBytes), image.Id);
    const config = { mediaType: "application/vnd.oci.image.config.v1+json", digest: ociHash(configBytes), size: configBytes.length };
    const manifestBytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json", config,
      layers: layers.map(bytes => ({ mediaType: "application/vnd.oci.image.layer.v1.tar", digest: ociHash(bytes), size: bytes.length })) }));
    const oci = join(source, "oci"); await mkdir(join(oci, "blobs", "sha256"), { recursive: true });
    for (const bytes of [configBytes, ...layers, manifestBytes]) await writeFile(join(oci, "blobs", "sha256", ociHash(bytes).slice(7)), bytes);
    await writeFile(join(oci, "oci-layout"), '{"imageLayoutVersion":"1.0.0"}');
    await writeFile(join(oci, "index.json"), JSON.stringify({ schemaVersion: 2, manifests: [{ mediaType: "application/vnd.oci.image.manifest.v1+json", digest: ociHash(manifestBytes), size: manifestBytes.length, platform: { os: "linux", architecture: "amd64" } }] }));
    const sourceTreeDigest = await artifactDigest(source, { profile: OCI_SOURCE_BUDGET_PROFILE });
    imported = await importOciRuntime({ root: source, sourceTreeDigest, platform: { os: "linux", architecture: "amd64" } });
    assert.deepEqual(imported.issues, [], "SYNTHETIC_OCI_IMPORT_REJECTED");
    const observed = await observeOciRuntime({ descriptor: imported.descriptor, expectedDescriptorDigest: imported.descriptorDigest, sinkImageDigest: builder,
      probePlan: { scenarios: [{ scenarioId: "normal", kind: "NORMAL", goal: "Read inert synthetic fixture", toolName: "first", argumentsJson: "{}" },
        { scenarioId: "boundary", kind: "ADVERSARIAL", goal: "Repeat bounded synthetic fixture", toolName: "second", argumentsJson: "{}" }] } });
    assert.deepEqual(observed.report.issues, [], "SYNTHETIC_OCI_OBSERVATION_REJECTED"); assert.equal(observed.report.ready, false);
    assert.equal(observed.report.checks.normalToolCallsSucceeded, true); assert.equal(observed.report.steps.discovery.mcp.pages, 2);
    const executionPolicy = ociExecutionPolicy(Object.fromEntries(["baseImageDigest", "baseCatalogueDigest", "trivyImageDigest", "databaseDigest", "observerDigest", "sinkImageDigest", "sinkCodeDigest"].map(name => [name, ociHash(`synthetic-review-anchor:${name}`)])));
    const binding = createOciReleaseBinding({ sourceReleaseId: `0x${"1".repeat(64)}`, descriptor: observed.observedDescriptor, executionPolicy });
    const identity = { schemaVersion: "mcpshield.gateway-prepared.v1", ...exactReleaseIdentity({ toolId: "oci:synthetic-native-gateway", ...binding }), binding, tools };
    const file = join(root, "gateway.json"); await writeFile(file, JSON.stringify(identity), { mode: 0o600 });
    const keys = generateKeyPairSync("ed25519"), context = { publicKey: keys.publicKey.export({ type: "spki", format: "pem" }), keyId: "synthetic-oci-issuer",
      apiToken: "SYNTHETIC_LOCAL_TOKEN", policyHash: `0x${"a".repeat(64)}`, chainId: 31337, registryContract: `0x${"b".repeat(40)}`, tenantId: "synthetic-oci", validatorSetVersion: 1 };
    let requests = 0, revokeAt = Infinity, unsigned = false, scenario = 0;
    server = createServer(async (request, response) => {
      assert.equal(request.url, "/v1/admission/check"); assert.equal(request.headers.authorization, `Bearer ${context.apiToken}`);
      const chunks = []; for await (const chunk of request) chunks.push(chunk); const body = JSON.parse(Buffer.concat(chunks));
      assert.equal(body.releaseId, identity.releaseId); assert.equal(body.artifactDigest, binding.artifactDigest); assert.equal(body.toolSurfaceHash, binding.toolSurfaceHash);
      const revoked = ++requests >= revokeAt, now = Date.now();
      const snapshot = { schemaVersion: "1.0.0", keyId: context.keyId, releaseId: body.releaseId, artifactDigest: body.artifactDigest, toolSurfaceHash: body.toolSurfaceHash,
        policyHash: context.policyHash, tenantId: context.tenantId, operationClass: body.operationClass, chainId: context.chainId, registryContract: context.registryContract,
        validatorSetVersion: 1, observedBlock: 123, blockHash: `0x${"c".repeat(64)}`, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30000).toISOString(),
        decision: revoked ? "BLOCK" : "ALLOW", status: revoked ? "REVOKED" : "VERIFIED", reasonCode: revoked ? "RELEASE_REVOKED" : "RELEASE_VERIFIED", reportUrl: `/v1/releases/${body.releaseId}` };
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ snapshot,
        ...(unsigned ? {} : { signature: sign(null, Buffer.from(canonicalJson(snapshot)), keys.privateKey).toString("base64url") }) }));
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const options = () => { requests = 0; context.registryContract = `0x${(++scenario).toString(16).padStart(40, "0")}`; return { ...context,
      apiBaseUrl: `http://127.0.0.1:${server.address().port}`, preparedIdentityPath: file, mode: "live", admissionMode: "strict", capture: true }; };
    const result = await runArtifact({ ...options(), input: wire({ id: 1, method: "tools/list" }, { id: 2, method: "tools/list", params: { cursor: "second" } }, call()) });
    assert.equal(result.code, 0); assert.equal(requests, 3); assert.equal(result.decision.decisionSource, "API");
    const replies = result.stdout.trim().split("\n").map(JSON.parse); assert.deepEqual(replies.map(reply => reply.id), [1, 2, 3]);
    assert.equal(replies[2].result.content[0].text, "SYNTHETIC_NATIVE_ISOLATION_OK"); assert.equal(result.stderr.includes("SYNTHETIC_CANDIDATE_STDERR_PRIVATE"), false);
    assert.deepEqual(await ownedContainers(), before);
    for (const when of [1, 2, 3, 4]) {
      revokeAt = when;
      await assert.rejects(runArtifact({ ...options(), input: wire(call("first"), { ...call(), id: 4 }) }), error => error instanceof AdmissionBlockedError && error.decision.releaseStatus === "REVOKED");
      assert.equal(requests, when); assert.deepEqual(await ownedContainers(), before);
    }
    revokeAt = Infinity; unsigned = true;
    await assert.rejects(runArtifact({ ...options(), input: wire(call()) }), /invalid proof metadata/); assert.equal(requests, 1); assert.deepEqual(await ownedContainers(), before);
    unsigned = false;
    await assert.rejects(runArtifact({ ...options(), input: wire(call("first", { linger: true })), executionTimeoutMs: 1000 }), /timed out/);
    assert.deepEqual(await ownedContainers(), before);
    // A recomputed, internally consistent commitment cannot substitute for local bytes.
    const alteredBinding = createOciReleaseBinding({ sourceReleaseId: binding.sourceReleaseId,
      descriptor: { ...binding.descriptor, rootfsDigest: ociHash("synthetic-false-filesystem") }, executionPolicy });
    await writeFile(file, JSON.stringify({ ...identity, ...exactReleaseIdentity({ toolId: identity.toolId, ...alteredBinding }), binding: alteredBinding }));
    await assert.rejects(runArtifact({ ...options(), input: wire(call()) }), /PREPARED_OCI_LOCAL_IMAGE_REJECTED/); assert.equal(requests, 0);
    await writeFile(file, JSON.stringify(identity));
    // Real CLI EOF must remove the container, not only kill the attached Docker client.
    const cliOptions = options(), env = { ...process.env, MCPSHIELD_MODE: "live", MCPSHIELD_API_URL: cliOptions.apiBaseUrl,
      MCPSHIELD_POLICY_HASH: context.policyHash, MCPSHIELD_CACHE_PUBLIC_KEY: context.publicKey, MCPSHIELD_CACHE_KEY_ID: context.keyId,
      MCPSHIELD_TENANT_ID: context.tenantId, MCPSHIELD_CONTROL_TOKEN: context.apiToken, MCPSHIELD_CHAIN_ID: String(context.chainId),
      MCPSHIELD_REGISTRY_CONTRACT: context.registryContract, MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict" };
    for (const key of ["MCPSHIELD_ARTIFACT_DIR", "MCPSHIELD_CONTROL_RELEASE_ID", "MCPSHIELD_RECEIPT_DB", "MCPSHIELD_ADMISSION_CACHE_FILE"]) delete env[key];
    const child = spawn(process.execPath, [fileURLToPath(new URL("../src/index.mjs", import.meta.url)), "stdio", "--prepared-identity", file],
      { env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "", timedOut = false;
    child.stdout.on("data", chunk => { stdout += chunk; }); child.stderr.on("data", chunk => { stderr += chunk; }); child.stdin.on("error", () => {});
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); }, 60000);
    try { child.stdin.end(wire(call("first", { linger: true }))); await new Promise((resolve, reject) => { child.once("close", resolve); child.once("error", () => reject(Error("SYNTHETIC_OCI_CLI_START_FAILED"))); }); }
    finally { clearTimeout(timer); }
    assert.equal(timedOut, false, "SYNTHETIC_OCI_CLI_EOF_TIMEOUT"); assert.match(stdout, /SYNTHETIC_NATIVE_ISOLATION_OK/);
    assert.equal(stderr.includes("SYNTHETIC_CANDIDATE_STDERR_PRIVATE"), false); assert.deepEqual(await ownedContainers(), before);
    assert.equal(await artifactDigest(source, { profile: OCI_SOURCE_BUDGET_PROFILE }), sourceTreeDigest);
  } finally {
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    await imported?.cleanup?.();
    if (built) await docker(["image", "rm", tag]);
    await removeFixtureSnapshot(root);
    assert.deepEqual(await ownedContainers(), before);
  }
});
