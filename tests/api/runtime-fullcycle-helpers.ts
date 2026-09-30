import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";

// Diagnostics are a closed vocabulary, never a candidate/provider message or path.
export function safeGatewayChildCode(error: any): string {
  const codes = ["GATEWAY_CHILD_FAILED", "GATEWAY_CHILD_EXPOSED_PRIVATE_CONFIG", "GATEWAY_CHILD_TIMEOUT_OR_OUTPUT_LIMIT", "GATEWAY_CHILD_INVALID_OUTPUT",
    "GATEWAY_ADMISSION_TRANSPORT_UNAVAILABLE", "GATEWAY_SIGNED_ADMISSION_REJECTED", "INPUT_LIMIT", "UNEXPECTED_EXECUTION",
    "PREPARED_IDENTITY_FILE_INVALID", "PREPARED_IDENTITY_INVALID", "PREPARED_TOOL_SURFACE_INVALID", "PREPARED_RELEASE_ID_MISMATCH",
    "PREPARED_LINUX_DOCKER_REQUIRED", "PREPARED_CONTROL_RELEASE_MISMATCH", "PREPARED_DOCKER_COMMAND_FAILED", "PREPARED_DOCKER_RESPONSE_INVALID",
    "PREPARED_OCI_LOCAL_IMAGE_REJECTED", "PREPARED_OCI_RUNTIME_MISMATCH", "PREPARED_OCI_DEFAULT_SECCOMP_REQUIRED", "PREPARED_CONTAINER_CLEANUP_FAILED"];
  if (codes.includes(error?.message)) return error.message;
  if (error?.name === "AdmissionTransportUnavailableError") return "GATEWAY_ADMISSION_TRANSPORT_UNAVAILABLE";
  if (["Signed admission expired or has an invalid lifetime", "Signed admission signature is invalid", "Signed admission identity or policy mismatch",
    "Signed admission contains invalid proof metadata", "Invalid signed admission snapshot fields", "Invalid signed admission response"].includes(error?.message)) return "GATEWAY_SIGNED_ADMISSION_REJECTED";
  return "GATEWAY_CHILD_FAILED";
}

export function completedGateways(attempts: PromiseSettledResult<any>[]) {
  return attempts.map((attempt, index) => {
    assert.equal(attempt.status, "fulfilled", `Gateway child ${index + 1}: ${attempt.status === "rejected" ? safeGatewayChildCode(attempt.reason) : "COMPLETED"}`);
    return (attempt as PromiseFulfilledResult<any>).value;
  });
}

// Integration-test process isolation only. Configuration is bounded private stdin,
// never command-line flags or inherited operator credentials.
export function privateNode(script: string, config: Record<string, any>, timeoutMs = 30000): Promise<any> {
  const input = JSON.stringify(config); assert.ok(Buffer.byteLength(input) <= 32768);
  const secrets = [config.apiToken, config.token, ...config.privateKeys ?? []].filter(value => typeof value === "string" && value.length);
  return new Promise((resolve, reject) => {
    const child = execFile(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
      env: { ...getDefaultEnvironment(), MCPSHIELD_TELEMETRY_ENABLED: "false" }, windowsHide: true, timeout: timeoutMs, maxBuffer: 65536,
    }, (error, stdout, stderr) => {
      clearTimeout(force);
      if (secrets.some(secret => stdout.includes(secret) || stderr.includes(secret))) { reject(Error("GATEWAY_CHILD_EXPOSED_PRIVATE_CONFIG")); return; }
      if (error) {
        let code = "GATEWAY_CHILD_FAILED";
        try {
          const value = JSON.parse(stderr.trim().split("\n").at(-1)!);
          if (value?.event === "gateway_child_failed" && Object.keys(value).sort().join() === "code,event") code = safeGatewayChildCode({ message: value.code });
        } catch { /* Raw child output is deliberately discarded. */ }
        reject(Error(error.killed ? "GATEWAY_CHILD_TIMEOUT_OR_OUTPUT_LIMIT" : code)); return;
      }
      try { resolve(JSON.parse(stdout.trim())); } catch { reject(Error("GATEWAY_CHILD_INVALID_OUTPUT")); }
    });
    // Allow the actual Gateway SIGTERM handler to remove its exact owned container;
    // force-stop only this child if graceful cleanup exceeds five more seconds.
    const force = setTimeout(() => child.kill("SIGKILL"), timeoutMs + 5000);
    child.stdin?.on("error", () => {}); child.stdin?.end(input);
  });
}

export const deniedGatewayChild = `
  import { AdmissionBlockedError, runArtifact } from ${JSON.stringify(new URL("../../apps/gateway/src/index.mjs", import.meta.url).href)};
  import { safeGatewayChildCode } from ${JSON.stringify(import.meta.url)};
  try {
    let input = ''; for await (const chunk of process.stdin) { input += chunk; if (Buffer.byteLength(input) > 32768) throw Error('INPUT_LIMIT'); }
    const options = JSON.parse(input);
    try { await runArtifact({ ...options, executionTimeoutMs: 2000, capture: true }); throw Error('UNEXPECTED_EXECUTION'); }
    catch (error) {
      if (!(error instanceof AdmissionBlockedError)) throw error;
      const d = error.decision;
      process.stdout.write(JSON.stringify({ pid: process.pid, releaseId: d.releaseId, decision: d.decision, status: d.releaseStatus,
        reasonCode: d.reasonCode, source: d.source, cacheHit: d.cacheHit }));
    }
  } catch (error) { process.stderr.write(JSON.stringify({ event: 'gateway_child_failed', code: safeGatewayChildCode(error) }) + '\\n'); process.exitCode = 1; }
`;

export async function dockerEvents(since: string) {
  const until = new Date().toISOString();
  const { stdout } = await promisify(execFile)("docker", ["events", "--since", since, "--until", until, "--format", "{{json .}}"],
    { windowsHide: true, timeout: 10000, maxBuffer: 262144 });
  const events = stdout.trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
  // Docker retains 256 historical events. This bounded local window is not a
  // durable audit log; reject a potentially truncated evidence window.
  assert.ok(events.length < 256, "DOCKER_EVENT_WINDOW_POSSIBLY_TRUNCATED");
  return events.filter(event => event.Type === "container" && event.Actor?.Attributes?.["io.mcpshield.gateway.owner"]);
}
