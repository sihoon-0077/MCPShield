import { createServer } from "node:http";
import { Interface } from "ethers";
import { bytes32, exactReleaseIdentity } from "../../../../packages/contracts-sdk/src/v2-identity.mjs";
import { releaseRegistryV2Abi } from "../../../../packages/contracts-sdk/src/v2-registry.mjs";

export const h = character => `0x${character.repeat(64)}`;
// Synthetic wire fixture: RPC rejection checks, not real validators or a real chain.
export async function syntheticRpc(name = "reader-test") {
  const registry = `0x${"1".repeat(40)}`, validators = `0x${"2".repeat(40)}`;
  const iface = new Interface(releaseRegistryV2Abi), validatorIface = new Interface(["function version() view returns(uint32)"]);
  const identity = { ...exactReleaseIdentity({ toolId: `npm:${name}`, artifactDigest: h("a"), manifestDigest: h("b"), toolSurfaceHash: h("c") }),
    artifactDigest: `sha256:${"a".repeat(64)}`, manifestDigest: `sha256:${"b".repeat(64)}`, toolSurfaceHash: h("c") };
  const now = Math.floor(Date.now() / 1000), counts = new Map(), requests = [];
  const state = { mode: "valid", identity, policyHash: h("d"), registryContract: registry, chainId: 1337, counts, requests };
  const block = number => ({ number: `0x${number.toString(16)}`, hash: h(String(number)), parentHash: h(String(number - 1)), nonce: "0x0000000000000000",
    sha3Uncles: h("0"), logsBloom: "0x" + "00".repeat(256), transactionsRoot: h("0"), stateRoot: h("0"), receiptsRoot: h("0"), miner: registry,
    difficulty: "0x0", totalDifficulty: "0x0", extraData: "0x", gasLimit: "0x1c9c380", gasUsed: "0x0", timestamp: `0x${(now + (state.mode === "stale-head" ? -31 : state.mode === "future-head" ? 10 : 0)).toString(16)}`, transactions: [], uncles: [] });
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const call = JSON.parse(Buffer.concat(chunks).toString("utf8")); requests.push({ method: call.method, path: request.url, authorization: request.headers.authorization });
    if (state.mode === "timeout") return;
    let result;
    if (call.method === "eth_chainId") result = "0x539";
    else if (call.method === "eth_getBlockByNumber") {
      const tag = call.params[0], count = (counts.get(tag) ?? 0) + 1; counts.set(tag, count);
      result = block(tag === "latest" ? 3 : Number(BigInt(tag)));
      if (state.mode === "zero-head" && tag === "latest" || state.mode === "zero-confirmed" && tag === "0x2") result.hash = h("0");
      if ((state.mode === "latest-reorg" && tag === "latest" || state.mode === "confirmed-reorg" && tag === "0x2") && count > 1) result.hash = h("f");
      if (state.mode === "moving-head" && tag === "latest" && count > 1) result = block(4);
    } else if (call.method === "eth_call") {
      if (call.params[0].to.toLowerCase() === validators) result = validatorIface.encodeFunctionResult("version", [1]);
      else {
        const parsed = iface.parseTransaction({ data: call.params[0].data });
        if (parsed.name === "validators") result = iface.encodeFunctionResult(parsed.name, [validators]);
        else if (parsed.name === "releases") result = iface.encodeFunctionResult(parsed.name, [state.mode === "identity" ? h("e") : identity.toolId,
          bytes32(identity.artifactDigest), bytes32(identity.manifestDigest), bytes32(identity.toolSurfaceHash), true]);
        else {
          const confirmed = call.params[1] === "0x2";
          result = iface.encodeFunctionResult("getDecision", [[state.mode === "attestation-drift" && confirmed ? h("e") : h("d"),
            now + (state.mode === "future-validity" ? 30 : -10), now + (state.mode === "expired" ? -1 : 3600), 0, 1, 2, 0, state.mode === "revoked" && !confirmed ? 3 : 1]]);
        }
      }
    } else { response.writeHead(400).end(); return; }
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: call.id, result }));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return Object.assign(state, { rpcUrls: [`http://127.0.0.1:${server.address().port}`],
    close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } });
}
