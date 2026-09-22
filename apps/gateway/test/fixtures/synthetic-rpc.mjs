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
  const state = { mode: "valid", routeModes: {}, identity, policyHash: h("d"), registryContract: registry, chainId: 1337, counts, requests };
  const block = (number, mode = state.mode) => ({ number: `0x${number.toString(16)}`, hash: h(String(number)), parentHash: h(String(number - 1)), nonce: "0x0000000000000000",
    sha3Uncles: h("0"), logsBloom: "0x" + "00".repeat(256), transactionsRoot: h("0"), stateRoot: h("0"), receiptsRoot: h("0"), miner: registry,
    difficulty: "0x0", totalDifficulty: "0x0", extraData: "0x", gasLimit: "0x1c9c380", gasUsed: "0x0", timestamp: `0x${(now + (mode.startsWith("stale-head") ? -31 : mode === "future-head" ? 10 : 0)).toString(16)}`, transactions: [], uncles: [] });
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const call = JSON.parse(Buffer.concat(chunks).toString("utf8")); requests.push({ method: call.method, path: request.url, params: call.params, authorization: request.headers.authorization });
    const mode = state.routeModes[request.url] ?? state.mode;
    if (mode === "timeout") return;
    if (mode === "http503" || mode === "http403") { response.writeHead(mode === "http503" ? 503 : 403); response.write("synthetic-private-error-body"); return; }
    if (mode === "redirect") { response.writeHead(307, { location: "/healthy" }).end(); return; }
    if (mode === "oversized") { response.writeHead(200, { "content-length": "99999999" }); response.end(); return; }
    if (mode === "bad-json") { response.end("synthetic-not-json"); return; }
    if (mode === "rpc-error") { response.end(JSON.stringify({ jsonrpc: "2.0", id: call.id, error: { code: -32603, message: "synthetic-private-rpc-error" } })); return; }
    if (mode === "wrong-id") { response.end(JSON.stringify({ jsonrpc: "2.0", id: call.id + 1, result: "0x539" })); return; }
    let result;
    if (call.method === "eth_chainId") result = "0x539";
    else if (call.method === "eth_getBlockByNumber") {
      const tag = call.params[0], count = (counts.get(tag) ?? 0) + 1; counts.set(tag, count);
      if (mode === "advance-budget" && tag === "latest" && count >= 3) return;
      if (count > 1 && (mode === "after-head-reorg-timeout" && tag === "0x2" || mode === "after-confirmed-reorg-timeout" && tag === "latest")) return;
      result = block(tag === "latest" ? 3 : Number(BigInt(tag)), mode);
      if (mode === "zero-head" && tag === "latest" || mode === "zero-confirmed" && tag === "0x2") result.hash = h("0");
      if ((mode === "latest-reorg" && tag === "latest" || mode === "confirmed-reorg" && tag === "0x2") && count > 1) result.hash = h("f");
      if (count > 1 && (mode === "after-head-reorg-timeout" && tag === "latest" || mode === "after-confirmed-reorg-timeout" && tag === "0x2")) result.hash = h("f");
      if ((mode === "moving-head" || mode.startsWith("advance-")) && tag === "latest" && count > 1) result = block(4, mode);
      if (mode === "continuous-head" && tag === "latest") result = block(3 + Math.floor(count / 2), mode);
    } else if (call.method === "eth_call") {
      if (call.params[0].to.toLowerCase() === validators) {
        if (mode === "revoked-version-timeout") return;
        result = validatorIface.encodeFunctionResult("version", [1]);
      }
      else {
        const parsed = iface.parseTransaction({ data: call.params[0].data });
        if (mode === "mixed-failure") {
          if (parsed.name === "releases") { response.end(JSON.stringify({ jsonrpc: "2.0", id: call.id, result: "invalid-abi" })); return; }
          if (parsed.name === "getDecision") return;
        }
        if (parsed.name === "getDecision" && (["identity-timeout", "stale-head-timeout", "zero-validator-timeout"].includes(mode) || (mode === "partial-negative" || mode === "expired-timeout") && call.params[1] === "0x2")) return;
        if (parsed.name === "validators") result = iface.encodeFunctionResult(parsed.name, [mode === "zero-validator-timeout" ? `0x${"0".repeat(40)}` : validators]);
        else if (parsed.name === "releases") result = iface.encodeFunctionResult(parsed.name, [mode === "identity" || mode === "identity-timeout" || mode === "advance-identity" && call.params[1] === "0x4" ? h("e") : identity.toolId,
          bytes32(identity.artifactDigest), bytes32(identity.manifestDigest), bytes32(identity.toolSurfaceHash), true]);
        else {
          const confirmed = call.params[1] === "0x2";
          result = iface.encodeFunctionResult("getDecision", [[mode === "attestation-drift" && confirmed || mode === "advance-drift" && call.params[1] === "0x3" && (counts.get("latest") ?? 0) >= 3 ? h("e") : h("d"),
            now + (mode === "future-validity" ? 30 : -10), now + (mode === "expired" || mode === "expired-timeout" || mode === "advance-expired" && call.params[1] === "0x4" ? -1 : 3600), 0, 1, 2, 0,
            (mode === "revoked" || mode === "stale-head-revoked" || mode === "revoked-version-timeout" || mode === "advance-negative" || mode === "partial-negative") && !confirmed || mode === "advance-revoked" && call.params[1] === "0x4" ? 3 : 1]]);
        }
      }
    } else { response.writeHead(400).end(); return; }
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: call.id, result }));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  return Object.assign(state, { rpcUrls: [`http://127.0.0.1:${server.address().port}`],
    close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } });
}
