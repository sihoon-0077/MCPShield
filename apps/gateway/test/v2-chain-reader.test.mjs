import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { Interface } from "ethers";
import { v2ChainReader } from "../../../packages/contracts-sdk/src/v2-chain-reader.mjs";
import { bytes32, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
import { releaseRegistryV2Abi } from "../../../packages/contracts-sdk/src/v2-registry.mjs";

test("plain Node shared reader pins exact identity, both decision views and uncached canonical block references", async () => {
  // Synthetic JSON-RPC responses test protocol rejection, not an on-chain quorum.
  const h = character => `0x${character.repeat(64)}`, registry = `0x${"1".repeat(40)}`, validators = `0x${"2".repeat(40)}`;
  const iface = new Interface(releaseRegistryV2Abi), validatorIface = new Interface(["function version() view returns(uint32)"]);
  const release = { ...exactReleaseIdentity({ toolId: "npm:reader-test", artifactDigest: h("a"), manifestDigest: h("b"), toolSurfaceHash: h("c") }),
    artifactDigest: h("a"), manifestDigest: h("b"), toolSurfaceHash: h("c") }, policy = { policyHash: h("d") };
  const now = Math.floor(Date.now() / 1000), counts = new Map(); let mode = "valid";
  const block = number => ({ number: `0x${number.toString(16)}`, hash: h(String(number)), parentHash: h(String(number - 1)), nonce: "0x0000000000000000",
    sha3Uncles: h("0"), logsBloom: "0x" + "00".repeat(256), transactionsRoot: h("0"), stateRoot: h("0"), receiptsRoot: h("0"), miner: registry,
    difficulty: "0x0", totalDifficulty: "0x0", extraData: "0x", gasLimit: "0x1c9c380", gasUsed: "0x0", timestamp: `0x${now.toString(16)}`, transactions: [], uncles: [] });
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const call = JSON.parse(Buffer.concat(chunks).toString("utf8")); let result;
    if (call.method === "eth_chainId") result = "0x539";
    else if (call.method === "eth_getBlockByNumber") {
      const tag = call.params[0], count = (counts.get(tag) ?? 0) + 1; counts.set(tag, count);
      result = block(tag === "latest" ? 3 : Number(BigInt(tag)));
      if ((mode === "latest-reorg" && tag === "latest" || mode === "confirmed-reorg" && tag === "0x2") && count > 1) result.hash = h("f");
      if (mode === "moving-head" && tag === "latest" && count > 1) result = block(4);
    } else if (call.method === "eth_call") {
      if (call.params[0].to.toLowerCase() === validators) result = validatorIface.encodeFunctionResult("version", [1]);
      else {
        const parsed = iface.parseTransaction({ data: call.params[0].data });
        if (parsed.name === "validators") result = iface.encodeFunctionResult(parsed.name, [validators]);
        else if (parsed.name === "releases") result = iface.encodeFunctionResult(parsed.name, [mode === "identity" ? h("e") : release.toolId,
          bytes32(release.artifactDigest), bytes32(release.manifestDigest), bytes32(release.toolSurfaceHash), true]);
        else {
          const confirmed = call.params[1] === "0x2";
          result = iface.encodeFunctionResult("getDecision", [[mode === "attestation-drift" && confirmed ? h("e") : h("d"), now - 10, now + 3600, 0, 1, 2, 0, mode === "revoked" && !confirmed ? 3 : 1]]);
        }
      }
    } else throw new Error("Unexpected synthetic RPC method");
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: call.id, result }));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const reader = v2ChainReader({ rpcUrls: [`http://127.0.0.1:${server.address().port}`], registryContract: registry, chainId: 1337, confirmations: 2 });
  try {
    const accepted = await reader(release, policy);
    assert.equal(accepted.status, "VERIFIED"); assert.equal(accepted.observedBlock, 2); assert.equal(accepted.blockHash, h("2"));
    assert.equal(counts.get("latest"), 2); assert.equal(counts.get("0x2"), 2, "Canonical recheck must reach the transport instead of ethers cache");
    for (mode of ["identity", "latest-reorg", "confirmed-reorg", "moving-head"]) { counts.clear(); await assert.rejects(reader(release, policy), /STATUS_UNAVAILABLE/); }
    mode = "attestation-drift"; counts.clear(); assert.equal((await reader(release, policy)).unavailable, true);
    mode = "revoked"; counts.clear(); const revoked = await reader(release, policy);
    assert.equal(revoked.status, "REVOKED"); assert.equal(revoked.observedBlock, 3);
    reader.close(); await assert.rejects(reader(release, policy), /STATUS_UNAVAILABLE/);
  } finally { reader.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
