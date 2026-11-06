// ADR-008 rehearsal stack without Docker: the operator API (/v1 control plane on ReleaseRegistryV3) with its outbox and
// indexer, three validators that each scan their own copy and vote through the operator relay, and the dashboard.
//   node --import tsx scripts/demo/v3-local-stack.mts                 in-process Ganache with a fresh V3 deployment
//   node --import tsx scripts/demo/v3-local-stack.mts --smoke         same, drives 1.0.0 and 1.0.1 itself, checks, exits
//   node --import tsx scripts/demo/v3-local-stack.mts --seed          drives them the same way, then keeps running (gateway-scene.mts)
//   node --import tsx scripts/demo/v3-local-stack.mts --base-sepolia  V3 on Base Sepolia: sends real testnet transactions
// Loopback only. Private keys are never printed or written; the dashboard login token is generated per data directory.
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import ganache from "ganache";
import { Contract, Wallet, ZeroHash } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { startScannerHeartbeat } from "../../apps/api/src/worker-health.js";
import { V2Relayer, enqueueChainAction, reconcileV2Actions, runChainActionOnce } from "../../apps/api/src/chain-outbox.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
import { indexV2 } from "../../apps/indexer/src/v2-indexer.js";
import { runValidatorV3 } from "../../apps/validator/src/v3.js";
import { defaultPolicy, hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { bytes32, createReleaseRegistryV3 } from "../../packages/contracts-sdk/src/v3.js";
// @ts-expect-error Resolver is shared ESM JavaScript.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";
// @ts-expect-error The eval40 adapter is shared ESM JavaScript.
import { DEFAULT_UPSTREAMS, createEvalAiAdapter } from "../../benchmarks/eval40/ai-adapter.mjs";

const { values } = parseArgs({ options: {
  "base-sepolia": { type: "boolean", default: false }, deploy: { type: "boolean", default: false }, deployment: { type: "string" }, "index-from": { type: "string" },
  "api-port": { type: "string", default: "3001" }, "dashboard-port": { type: "string", default: "3000" }, "no-dashboard": { type: "boolean", default: false },
  data: { type: "string" }, smoke: { type: "boolean", default: false }, seed: { type: "boolean", default: false }, ai: { type: "string", multiple: true }, order: { type: "string", default: "C,A,B" },
} });
const repo = resolve(import.meta.dirname, "../.."), baseSepolia = values["base-sepolia"];
process.chdir(repo); // the API resolves the shipped demo fixtures relative to the repository root
const FIXTURES = ["mail-mcp-1.0.0", "mail-mcp-1.0.1"].map((name) => join(repo, "demo/fixtures", name));
const NAMES = ["A", "B", "C"] as const;
type Name = (typeof NAMES)[number];
// Validators vote one by one, each after the validator before it has finished with the same scan. The default puts C first:
// C holds the emergency brake in the demo story, so its quarantine always lands before a FAIL quorum whatever the machine's speed.
const ORDER = values.order!.split(",") as Name[];
if (ORDER.length !== 3 || NAMES.some((name) => !ORDER.includes(name))) throw new Error("ORDER_INVALID");
const TURN_WAIT_MS = 180_000; // a stuck validator does not hold the others forever
const time = () => new Date().toLocaleTimeString("ko-KR", { hour12: false });
const log = (who: string, text: string) => console.log(`${time()} [${who}] ${text}`);
const code = (error: any) => /^[A-Z][A-Z0-9_:]{2,80}$/.test(error?.message ?? "") ? error.message : "UNEXPECTED_ERROR";
const short = (value?: string | null) => value ? `${value.slice(0, 10)}…${value.slice(-4)}` : "없음";
if (values.deploy && !baseSepolia) throw new Error("DEPLOY_FLAG_IS_FOR_BASE_SEPOLIA");

type Chain = { label: string; rpc: string; chainId: number; relayerKey: string; validatorKeys: string[]; registry: string; policyRegistry: string;
  deploymentBlock: number; confirmations: number; maxBlocks: number; readTimeoutMs?: number; close: () => Promise<unknown> };

async function localChain(): Promise<Chain> {
  // Compile before the chain starts: a multi-second solc stall during chain traffic times out RPC requests.
  for (const name of ["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV3"]) compileReleaseRegistry(name);
  // A block every second, like a public L2: round windows and the Gateway's freshness bound need a moving head.
  const server: any = ganache.server({ logging: { quiet: true }, chain: { chainId: 31337 }, miner: { blockTime: 1 }, wallet: { deterministic: true, totalAccounts: 4 } });
  await server.listen(0, "127.0.0.1");
  const rpc = `http://127.0.0.1:${server.address().port}`;
  const keys = (Object.values(server.provider.getInitialAccounts()) as { secretKey: string }[]).map((account) => account.secretKey);
  const deployment = await deployV2(rpc, keys[0], keys.slice(1, 4).map((key) => new Wallet(key).address), 31337, undefined, "ReleaseRegistryV3");
  return { label: "로컬 Ganache · chain 31337 (테스트 키)", rpc, chainId: 31337, relayerKey: keys[0], validatorKeys: keys.slice(1, 4),
    registry: deployment.releaseRegistry.address, policyRegistry: deployment.policyRegistry.address, deploymentBlock: deployment.validatorRegistry.blockNumber,
    confirmations: 1, maxBlocks: 500, close: () => server.close() };
}

async function baseSepoliaChain(dataDir: string): Promise<Chain> {
  const secrets = process.env.MCPSHIELD_SECRETS_DIR ?? join(homedir(), ".mcpshield-secrets");
  const key = async (name: string) => {
    const value = (await readFile(join(secrets, `${name}.key`), "utf8")).trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`KEY_FORMAT_INVALID:${name.toUpperCase().replace(/-/g, "_")}`);
    return value;
  };
  const rpc = (process.env.CONTROL_V2_RPC_URLS ?? "https://sepolia.base.org").split(",")[0];
  const relayerKey = await key("deployer-relayer"), validatorKeys = [await key("validator-a"), await key("validator-b"), await key("validator-c")];
  let deployment: any;
  if (values.deploy) {
    deployment = await deployV2(rpc, relayerKey, validatorKeys.map((value) => new Wallet(value).address), 84532, undefined, "ReleaseRegistryV3");
    await writeFile(join(dataDir, "base-sepolia-v3-deployment.json"), `${JSON.stringify({ ...deployment, deployedAt: new Date().toISOString() }, null, 2)}\n`);
    log("체인", `새 V3 배포 완료 · registry ${deployment.releaseRegistry.address} · 기록 ${join(dataDir, "base-sepolia-v3-deployment.json")}`);
  } else deployment = JSON.parse(await readFile(resolve(repo, values.deployment ?? "deployments/base-sepolia-v3.json"), "utf8"));
  if (deployment.chainId !== 84532 || deployment.registryContract !== "ReleaseRegistryV3") throw new Error("DEPLOYMENT_NOT_BASE_SEPOLIA_V3");
  return { label: "Base Sepolia · chain 84532 (실제 테스트넷 거래)", rpc, chainId: 84532, relayerKey, validatorKeys,
    registry: deployment.releaseRegistry.address, policyRegistry: deployment.policyRegistry.address,
    deploymentBlock: Number(values["index-from"] ?? deployment.releaseRegistry.blockNumber), confirmations: 2, maxBlocks: 200,
    readTimeoutMs: 3000, close: async () => {} }; // a public RPC read from Korea takes 1.0-2.5 s (ADR-009)
}

// Before any chain work: a mistyped --ai or a missing key must not cost a testnet deployment.
// --ai A=openai:gpt-6.1-terra --ai C=gemini:gemini-3.5-flash gives that validator its own AI witness (ADR-002: a witness can
// hold a release, never revoke it; a witness that does not answer holds a clean scan). OpenAI is called directly; Gemini goes
// through the eval40 loopback adapter, which turns the Responses call into Gemini's chat API. Keys stay in the secrets folder.
const secretsDir = process.env.MCPSHIELD_SECRETS_DIR ?? join(homedir(), ".mcpshield-secrets");
const aiScan: Partial<Record<Name, Record<string, unknown>>> = {}, aiLabel: string[] = [], aiAdapters: any[] = [];
for (const spec of values.ai ?? []) {
  const match = /^([ABC])=(openai|gemini):([A-Za-z0-9._:-]{1,128})$/.exec(spec);
  if (!match) throw new Error("AI_SPEC_INVALID");
  const [, name, provider, model] = match as unknown as [string, Name, "openai" | "gemini", string];
  if (provider === "openai") {
    aiScan[name] = { allowRemoteAi: true, aiProvider: "openai", aiModel: model, aiToken: (await readFile(join(secretsDir, "openai.key"), "utf8")).trim(), aiTimeoutMs: 120_000 };
  } else {
    const upstream = DEFAULT_UPSTREAMS[model];
    if (!upstream) throw new Error("AI_MODEL_UNKNOWN");
    const env = await readFile(join(secretsDir, "eval40.env"), "utf8").catch(() => "");
    const key = /^GEMINI_API_KEY=(.+)$/m.exec(env)?.[1]?.trim() ?? (await readFile(join(secretsDir, "gemini.key"), "utf8")).trim();
    const token = randomBytes(24).toString("hex");
    const { server } = createEvalAiAdapter({ token, keys: { [model]: key }, upstreams: { [model]: upstream } });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    aiAdapters.push(server);
    aiScan[name] = { allowRemoteAi: true, aiProvider: "openai", aiModel: model, aiUrl: `http://127.0.0.1:${server.address().port}/v1/responses`, aiToken: token, aiTimeoutMs: 120_000 };
  }
  aiLabel.push(`${name}=${model}`);
}
const dataDir = values.data ? resolve(values.data) : await mkdtemp(join(tmpdir(), "mcpshield-v3-stack-"));
await mkdir(dataDir, { recursive: true });
// Per data directory: login tokens, the evidence encryption key and the admission signing key survive a restart with --data.
const stackFile = join(dataDir, "stack-local.json");
const stack = await readFile(stackFile, "utf8").then(JSON.parse).catch(async () => {
  const token = () => randomBytes(24).toString("hex"), signing = generateKeyPairSync("ed25519");
  const created = { tenantId: "v3-demo", adminToken: token(), readerToken: token(), validatorTokens: NAMES.map(() => token()), evidenceKey: randomBytes(32).toString("hex"),
    signingKey: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), publicKey: signing.publicKey.export({ format: "pem", type: "spki" }).toString(), signingKeyId: "v3-stack" };
  await writeFile(stackFile, `${JSON.stringify(created, null, 2)}\n`, { mode: 0o600 });
  return created;
});
const chain = baseSepolia ? await baseSepoliaChain(dataDir) : await localChain();
const policyHash = hash(defaultPolicy);

const relayer = new V2Relayer(chain.rpc, chain.registry, chain.chainId, chain.relayerKey, 3);
const store = await ControlStore.open(join(dataDir, "control.sqlite"));
const options: ControlOptions = { store, credentials: [{ token: stack.adminToken, tenantId: stack.tenantId, role: "admin" }, { token: stack.readerToken, tenantId: stack.tenantId, role: "reader" },
  ...stack.validatorTokens.map((token: string) => ({ token, tenantId: stack.tenantId, role: "operator" as const }))],
  artifactPath: join(dataDir, "artifacts"), evidencePath: join(dataDir, "evidence"), evidenceKey: stack.evidenceKey, signingKey: stack.signingKey, signingKeyId: stack.signingKeyId,
  v2Relayer: relayer, chainDecision: v2ChainReader({ rpcUrls: [chain.rpc], registryContract: chain.registry, chainId: chain.chainId, confirmations: chain.confirmations, timeoutMs: chain.readTimeoutMs }) };
const app = await buildApp({ databasePath: ":memory:", adminApiToken: randomBytes(24).toString("hex"), scannerApiToken: randomBytes(24).toString("hex"), controlPlane: options });
await app.listen({ host: "127.0.0.1", port: Number(values["api-port"]) }); // --api-port 0 picks a free port
const apiUrl = `http://127.0.0.1:${(app.server.address() as any).port}`;
await writeFile(join(dataDir, "gateway-trust.json"), `${JSON.stringify({ apiUrl, tenantId: stack.tenantId, keyId: stack.signingKeyId, publicKey: stack.publicKey,
  chainId: chain.chainId, registryContract: chain.registry, rpcUrl: chain.rpc, policyHash, validatorSetVersion: 1 }, null, 2)}\n`);

// Same liveness record as control-worker-cli, so the console's health panel can see the in-process scan worker.
const heartbeat = startScannerHeartbeat(store, options, "ALL");
// Shutdown runs in two steps: validators stop taking new scans and finish the vote in hand while the outbox and the indexer
// keep running (a relayed vote settles only when the outbox marks it sent); then everything else stops.
let accepting = true, stopping = false;
const loops: Promise<void>[] = [], validatorLoops: Promise<void>[] = [];
const loop = (who: string, everyMs: number, work: () => Promise<unknown>, running = () => !stopping, group = loops) => group.push((async () => {
  while (running()) {
    try { await work(); } catch (error) { log(who, `실패 · ${code(error)}`); }
    for (let waited = 0; waited < everyMs && running(); waited += 250) await sleep(250);
  }
})());
const turns = new Map<string, { settled: boolean; done: () => void }>();
const turn = (scanId: string, name: string) => {
  const key = `${scanId}:${name}`;
  if (!turns.has(key)) { const entry = { settled: false, done: () => { entry.settled = true; } }; turns.set(key, entry); }
  return turns.get(key)!;
};
const waitTurn = async (scanId: string, name: Name) => {
  const before = ORDER[ORDER.indexOf(name) - 1];
  if (!before) return;
  for (const deadline = Date.now() + TURN_WAIT_MS; accepting && !turn(scanId, before).settled && Date.now() < deadline;) await sleep(250);
};
loop("운영사 검사", 1000, async () => { while (!stopping && await runControlWorkerOnce(store, options)) log("운영사 검사", "검사 1건 완료"); });
loop("체인 전송", 1000, async () => { while (!stopping && await runChainActionOnce(store, relayer)); });
loop("인덱서", 3000, async () => {
  await reconcileV2Actions(store, relayer);
  await indexV2(store, relayer, { deploymentBlock: chain.deploymentBlock, confirmations: chain.confirmations, maxBlocks: chain.maxBlocks, readTimeoutMs: chain.readTimeoutMs });
});
// The default policy must be active on chain before any vote; already published = no transaction.
await enqueueChainAction(store, relayer, stack.tenantId, "PUBLISH_POLICY", { policyHash });

const reader: any = createReleaseRegistryV3(chain.registry, relayer.provider);
// REVOKED is terminal: the registry takes a late vote only in the round that revoked the release (TERMINAL_RELEASE). A vote for a
// later scan's round reverts, and the operator's outbox cannot tell that revert from an RPC outage (the hardened transport never
// passes JSON-RPC error bodies on), so it would retry for minutes while every later vote waits behind the same relayer nonce.
// revokedRound is set in the same transaction as revoked, so one read answers both (two reads may hit nodes at different heights).
// The operator API refuses such a round as well (RELEASE_REVOKED); skipping here saves the validator its scan and AI call.
const terminalRound = async (scan: any) => {
  const revokedRound: string = await reader.revokedRound(scan.releaseId);
  if (revokedRound === ZeroHash) return false;
  const validators = new Contract(await reader.validators(), ["function version() view returns(uint32)"], relayer.provider);
  const round = await reader.roundIdOf(scan.releaseId, scan.policyHash, Math.floor(Date.parse(scan.result.validFrom) / 1000),
    Math.floor(Date.parse(scan.result.validUntil) / 1000), Number(await validators.version()));
  return round !== revokedRound;
};
for (const [index, name] of NAMES.entries()) {
  const who = `검증자 ${name}`, token = stack.validatorTokens[index];
  // Each validator keeps its own copy of the fixtures; identity is recomputed from those bytes, never taken from the operator.
  const copies = await Promise.all(FIXTURES.map(async (source) => {
    const dir = join(dataDir, `validator-${name}`, basename(source));
    await cp(source, dir, { recursive: true, force: true });
    const local = await resolveArtifact({ sourceType: "local", locator: dir });
    return { dir, label: basename(source), identity: [bytes32(local.artifactDigest), bytes32(local.manifestDigest), bytes32(local.toolSurfaceHash)].join() };
  }));
  const handled = new Set<string>(), retries = new Map<string, number>(), retryAt = new Map<string, number>();
  const address = new Wallet(chain.validatorKeys[index]).address.toLowerCase();
  // Did the operator receive this validator's vote for the scan? An unreadable store counts as yes, so nothing is signed twice.
  const received = (scan: any) => store.events(stack.tenantId, scan.releaseId).then((events) => events.some((event) => event.eventName === "validator.vote.received"
    && event.payload?.scanId === scan.scanId && String(event.payload?.validator).toLowerCase() === address), () => true);
  loop(who, 2000, async () => {
    const response = await fetch(`${apiUrl}/v1/scans`, { headers: { authorization: `Bearer ${token}` } });
    if (!response.ok) throw new Error(`VALIDATOR_API_HTTP_${response.status}`);
    const scans = ((await response.json()).items as any[]).filter((scan) => scan.status === "COMPLETED" && scan.policyHash === policyHash && !handled.has(scan.scanId)).reverse();
    for (const scan of scans) {
      if (!accepting) return;
      const due = retryAt.get(scan.scanId);
      if (due !== undefined) {
        if (Date.now() < due) continue;
        retryAt.delete(scan.scanId);
        // A POST that timed out on this side may still have reached the operator: look again, well after the handler would finish.
        if (await received(scan)) { handled.add(scan.scanId); log(who, `검사 ${scan.scanId.slice(0, 8)} · 운영사가 이미 표를 받음 · 다시 서명하지 않음`); continue; }
      }
      const onChain = await reader.releases(scan.releaseId);
      if (!onChain.exists) continue; // not registered on chain yet: look again on the next pass
      if (await terminalRound(scan)) {
        handled.add(scan.scanId);
        log(who, `검사 ${scan.scanId.slice(0, 8)} · 이미 폐기된 릴리스의 새 라운드라 투표하지 않음 (체인이 받지 않음)`);
        continue;
      }
      // The round starts at the operator scan's validFrom (wall clock); a validator refuses a window the chain head has not
      // reached yet (ROUND_WINDOW_INVALID) and would never retry. Blocks come every second or two: look again on the next pass.
      if (Math.floor(Date.parse(scan.result?.validFrom) / 1000) > Number((await relayer.provider.getBlock("latest"))?.timestamp ?? 0)) continue;
      handled.add(scan.scanId);
      const mine = turn(scan.scanId, name);
      try {
        await waitTurn(scan.scanId, name);
        if (!accepting) return;
        const copy = copies.find((item) => item.identity === [onChain.artifactDigest, onChain.manifestDigest, onChain.toolSurfaceDigest].join());
        if (!copy) { log(who, `검사 ${scan.scanId.slice(0, 8)} · 같은 바이트의 자기 사본이 없어 투표하지 않음`); continue; }
        try {
          const run = await runValidatorV3({ privateKey: chain.validatorKeys[index], rpcUrl: chain.rpc, chainId: chain.chainId, registryAddress: chain.registry, policyHash,
            artifactDir: copy.dir, evidenceDir: join(dataDir, `validator-${name}`, "evidence"), relay: { apiUrl, token, scanId: scan.scanId }, quarantine: name === "C",
            scan: aiScan[name] });
          const txs = run.transactions.map((tx: any) => `${tx.kind === "QUARANTINE" ? "긴급 격리" : "투표"} ${short(tx.txHash)}`).join(" · ");
          const witness = run.ai ? ` · AI 증인 ${run.ai.model} ${run.ai.status === "COMPLETED" ? "응답함" : "응답 없음"}` : "";
          log(who, `${copy.label} · 자기 검사 ${run.verdict}${run.basis.length ? ` (${run.basis.join(", ")})` : ""}${witness} · 증거 ${short(run.evidenceHash)} · ${run.skipped === "ALREADY_VOTED" ? "이미 투표함" : txs}`);
        } catch (error) {
          log(who, `${copy.label} · 투표 실패 · ${code(error)}`);
          // A public RPC that briefly refuses reads fails the vote before the operator has it (the API answers HTTP 400 for
          // RPC_TRUST_REJECTED). Such a scan gets up to three more tries, 45 s apart. Once the operator has received this validator's
          // vote for the scan it is never retried (checked now and again before the retry): a second run would sign a different
          // evidence file, and the API refuses it while the first is in the outbox (VOTE_RELAY_PENDING).
          // Only transport-shaped failures are retried; a 409 (expired window, revoked release, vote pending) stays final.
          const transient = /^(VALIDATOR_API_HTTP_(400|5\d\d)|RPC_TRUST_REJECTED|SERVICE_TRANSPORT_UNAVAILABLE|UNEXPECTED_ERROR)$/.test(code(error));
          const tried = (retries.get(scan.scanId) ?? 0) + 1;
          if (transient && await received(scan)) log(who, `${copy.label} · 운영사가 표를 받음 · 체인 기록은 운영사 전송기가 마무리`);
          else if (transient && tried <= 3) {
            retries.set(scan.scanId, tried); retryAt.set(scan.scanId, Date.now() + 45_000); handled.delete(scan.scanId);
            log(who, `${copy.label} · 45초 뒤 다시 시도 (${tried}/3)`);
          }
        }
      } finally { mine.done(); }
    }
  }, () => accepting, validatorLoops);
}

let dashboard: ChildProcess | undefined;
if (!values["no-dashboard"] && !values.smoke) {
  const port = values["dashboard-port"]!;
  dashboard = spawn(process.execPath, [join(repo, "node_modules/next/dist/bin/next"), "dev", "-p", port, "-H", "127.0.0.1"], { cwd: join(repo, "apps/dashboard"), stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, MCPSHIELD_API_URL: apiUrl, MCPSHIELD_PUBLIC_ORIGIN: `http://127.0.0.1:${port}`, MCPSHIELD_CONTROL_ALLOW_LOOPBACK_HTTP: "true",
      MCPSHIELD_DEMO_CONTROL_TOKEN: stack.adminToken,
      ...(baseSepolia ? { MCPSHIELD_V3_RPC_URL: chain.rpc, MCPSHIELD_V3_CHAIN_ID: String(chain.chainId), MCPSHIELD_V3_REGISTRY: chain.registry, MCPSHIELD_V3_POLICY_REGISTRY: chain.policyRegistry } : {}) } });
  dashboard.stdout?.on("data", (chunk: Buffer) => { if (/ready|error/i.test(chunk.toString())) log("대시보드", chunk.toString().trim().split("\n")[0].slice(0, 160)); });
  dashboard.stderr?.on("data", (chunk: Buffer) => { if (/error/i.test(chunk.toString())) log("대시보드", "오류 출력이 있습니다. --no-dashboard로 따로 띄워 확인하세요."); });
}

async function shutdown(exitCode = 0) {
  if (!accepting) return;
  accepting = false;
  dashboard?.kill();
  await Promise.race([Promise.allSettled(validatorLoops), sleep(120_000)]);
  stopping = true;
  await Promise.allSettled(loops);
  await heartbeat.stop();
  await app.close(); // also closes the store, the relayer and the chain reader
  for (const server of aiAdapters) server.close();
  await chain.close();
  if (!values.data) await rm(dataDir, { recursive: true, force: true });
  process.exit(exitCode);
}
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => void shutdown());

console.log([
  "", `MCPShield V3 로컬 시연 스택 · ${chain.label}`,
  `  ReleaseRegistryV3 ${chain.registry}`, `  운영 API ${apiUrl} (검증자 표 중계·인덱서 포함)`,
  ...(dashboard ? [`  대시보드 http://127.0.0.1:${values["dashboard-port"]} · 로그인 없이 관리자(admin)로 연결됩니다 (토큰은 ${stackFile} 의 adminToken)`] : []),
  `  검증자 A·B·C: 각자 사본을 검사하고 자기 증거에 서명해 운영사 중계로 투표합니다. C가 긴급 격리를 맡고, 순서는 ${ORDER.join(" → ")}입니다.`,
  `  AI 증인: ${aiLabel.length ? aiLabel.join(", ") : "없음 (규칙과 미끼 시험 환경만)"}`,
  "  진행: 새 릴리스 등록(fixture mail-mcp-1.0.0) → 관리자 온체인 등록 → 검사 요청 → 검증자 투표 → 실행 판정 조회. 이어서 mail-mcp-1.0.1.",
  `  데이터 ${dataDir}${values.data ? "" : " (종료 시 삭제)"} · 종료 Ctrl+C`, "",
].join("\n"));

if (values.smoke || values.seed) {
  // Same path as the dashboard: admin requests through the API; validators vote on their own; then check chain and admission.
  const auth = { authorization: `Bearer ${stack.adminToken}` };
  const post = async (url: string, payload: any = {}, headers: Record<string, string> = {}) => {
    const response = await app.inject({ method: "POST", url, headers: { ...auth, ...headers }, payload });
    if (response.statusCode >= 300) throw new Error(`SMOKE_HTTP_${response.statusCode}`);
    return response.json();
  };
  const waitFor = async <T,>(what: string, check: () => Promise<T | undefined>, timeoutMs = 240_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) { const value = await check().catch(() => undefined); if (value !== undefined) return value; await sleep(1000); }
    throw new Error(`SMOKE_TIMEOUT:${what}`);
  };
  try {
    const outcomes: Record<string, string> = {}, revokedEarlier: string[] = [];
    for (const [version, expected] of [["1.0.0", "VERIFIED"], ["1.0.1", "REVOKED"]] as const) {
      const release = (await post("/v1/releases/resolve", { sourceType: "fixture", locator: `mail-mcp-${version}` })).release;
      await post(`/v1/releases/${release.releaseId}/register`);
      await waitFor(`register ${version}`, async () => (await reader.releases(release.releaseId)).exists || undefined);
      // On a deployment that revoked it before (F604), this run's validators cast no vote on it: the check below then reads the
      // earlier revoking round, and the log says so instead of implying this run revoked it.
      if (await reader.revokedRound(release.releaseId) !== ZeroHash) revokedEarlier.push(version);
      // A fresh key per run: with a reused --data directory a fixed key would return yesterday's expired scan.
      const { scan } = await post("/v1/scans", { releaseId: release.releaseId, policyHash }, { "idempotency-key": `smoke-${version}-${randomBytes(8).toString("hex")}` });
      // This run's round must carry the three votes; an earlier approval or revocation on a reused --data or deployment does not
      // count, except a revocation from before this run (the validators cast nothing on a revoked release).
      const thisRound = (body: any) => body.rounds.find((round: any) => (revokedEarlier.includes(version) ? round.roundId === body.decisionRound : round.scanId === scan.scanId)
        && round.votes.filter((vote: any) => vote.cast).length === 3);
      const view = await waitFor(`votes ${version}`, async () => {
        const response = await app.inject({ url: `/v1/releases/${release.releaseId}/votes`, headers: auth }), body = response.json();
        return response.statusCode === 200 && body.status === expected && thisRound(body) ? body : undefined;
      });
      const admission = (await post("/v1/admission/check", { releaseId: release.releaseId, artifactDigest: release.artifactDigest, toolSurfaceHash: release.toolSurfaceHash,
        policyHash, mode: "strict", operationClass: "READ_PRIVATE" })).decision;
      outcomes[version] = `${view.status}${revokedEarlier.includes(version) ? " (이번 실행 전에 이미 폐기됨 · 이번 실행의 표 없음, 아래는 폐기 라운드의 표)" : ""} · 실행 판정 ${admission}`;
      log("점검", `mail-mcp ${version} · ${outcomes[version]} · ${thisRound(view).votes.map((vote: any) => `${short(vote.validator)} ${vote.verdict}`).join(", ")}`);
      if (admission !== (expected === "VERIFIED" ? "ALLOW" : "BLOCK")) throw new Error(`SMOKE_ADMISSION_MISMATCH:${version}`);
    }
    log("점검", revokedEarlier.includes("1.0.1") ? "통과 · 1.0.0 승인과 실행 허용, 그리고 이전에 폐기된 1.0.1의 실행 차단을 확인했습니다."
      : "통과 · 1.0.0 승인과 실행 허용, 1.0.1 폐기와 실행 차단을 확인했습니다.");
    if (values.smoke) await shutdown(0);
    else log("점검", `계속 실행합니다 · 두 회사 Gateway 장면: node --import tsx scripts/demo/gateway-scene.mts --stack "${dataDir}"`);
  } catch (error) { log("점검", `실패 · ${code(error)}`); await shutdown(1); }
}
