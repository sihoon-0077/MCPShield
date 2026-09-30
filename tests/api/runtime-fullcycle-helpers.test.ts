import assert from "node:assert/strict";
import { test } from "node:test";
import { completedGateways, deniedGatewayChild, privateNode, safeGatewayChildCode } from "./runtime-fullcycle-helpers.js";

test("Gateway failure diagnostics admit exact codes only and never raw errors/secrets", async () => {
  const secret = "SYNTHETIC_PRIVATE_TOKEN_123", privatePath = "C:/private/synthetic/config.json";
  assert.equal(safeGatewayChildCode(Error("PREPARED_OCI_LOCAL_IMAGE_REJECTED")), "PREPARED_OCI_LOCAL_IMAGE_REJECTED");
  assert.equal(safeGatewayChildCode({ name: "AdmissionTransportUnavailableError", message: secret }), "GATEWAY_ADMISSION_TRANSPORT_UNAVAILABLE");
  for (const message of [secret, privatePath, `PREPARED_OCI_LOCAL_IMAGE_REJECTED ${secret}`, "UNKNOWN_UPPERCASE_CODE"]) {
    assert.equal(safeGatewayChildCode(Error(message)), "GATEWAY_CHILD_FAILED");
    assert.throws(() => completedGateways([{ status: "rejected", reason: Error(message) }]), (error: any) => {
      assert.match(error.message, /Gateway child 1: GATEWAY_CHILD_FAILED/);
      assert.ok(!error.message.includes(message)); return true;
    });
    const script = `process.stderr.write(JSON.stringify({event:'gateway_child_failed',code:${JSON.stringify(message)}})+'\n');process.exitCode=1;`;
    await assert.rejects(privateNode(script, {}), { message: "GATEWAY_CHILD_FAILED" });
  }
  assert.throws(() => completedGateways([{ status: "rejected", reason: Error("GATEWAY_CHILD_TIMEOUT_OR_OUTPUT_LIMIT") }]), /GATEWAY_CHILD_TIMEOUT_OR_OUTPUT_LIMIT/);
  assert.deepEqual(completedGateways([{ status: "fulfilled", value: { decision: "BLOCK" } }]), [{ decision: "BLOCK" }]);
});

test("real denied child emits only a classified identity error before Docker or admission", async () => {
  await assert.rejects(privateNode(deniedGatewayChild, { mode: "live", policyHash: `0x${"1".repeat(64)}`,
    preparedIdentityPath: "deliberately-missing-private-identity.json", input: "{}\n", apiToken: "SYNTHETIC_PRIVATE_CONFIG_TOKEN" }),
  { message: "PREPARED_IDENTITY_FILE_INVALID" });
});
