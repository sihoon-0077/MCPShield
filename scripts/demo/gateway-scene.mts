// Final-demo scene for two companies (ADR-004/006) against a running V3 stack (v3-local-stack.mts, local or --base-sepolia):
//   Gateway A trusts the operator API of that stack, through a local relay the scene cuts to show an operator outage.
//   Gateway B trusts only company B's own API, started here: it resolves the same fixture bytes itself and reads
//   ReleaseRegistryV3 directly. B holds no chain key and sends no transaction; its admission signing key is made per run.
//   node --import tsx scripts/demo/gateway-scene.mts --stack <stack data dir> [--samples 20] [--rpc <RPC for B>] [--out <file>]
// Reads gateway-trust.json and the reader token from stack-local.json in the stack's data directory. Prints no token or key.
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
// @ts-expect-error Resolver is shared ESM JavaScript.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";

const { values } = parseArgs({ options: {
  stack: { type: "string" }, samples: { type: "string", default: "20" }, rpc: { type: "string" }, out: { type: "string" },
} });
if (!values.stack) throw new Error("STACK_DIR_REQUIRED");
const stackDir = resolve(values.stack), out = resolve(values.out ?? join(stackDir, "gateway-scene.json"));
const repo = resolve(import.meta.dirname, "../..");
process.chdir(repo); // the API resolves the shipped demo fixtures relative to the repository root
const samples = Number(values.samples);
if (!Number.isSafeInteger(samples) || samples < 1 || samples > 200) throw new Error("SAMPLES_INVALID");
const gatewayEntry = join(repo, "apps/gateway/src/index.mjs");
const CALL_TIMEOUT_MS = 15_000, CHILD_TIMEOUT_MS = 60_000, WARM_UP = 3;
const time = () => new Date().toLocaleTimeString("ko-KR", { hour12: false });
const log = (who: string, text: string) => console.log(`${time()} [${who}] ${text}`);
const short = (value?: string | null) => value ? `${value.slice(0, 10)}…${value.slice(-4)}` : "없음";
const host = (url: string) => new URL(url).host; // an RPC URL may carry a provider key in its path
const seconds = (ms: number) => `${(ms / 1000).toFixed(1)}초`;
const STATUS: Record<string, string> = { VERIFIED: "승인", REVOKED: "폐기", QUARANTINED: "격리", EXPIRED: "만료", UNVERIFIED: "미검증" };
const percentile = (list: number[], p: number) => {
  if (!list.length) return null;
  const sorted = [...list].sort((a, b) => a - b);
  return Number(sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)].toFixed(1));
};
const summary = (list: number[]) => ({ n: list.length, p50: percentile(list, 50), p95: percentile(list, 95), max: list.length ? Number(Math.max(...list).toFixed(1)) : null });
// Why the Gateway closed a session, from its own gateway_runtime_blocked line (same classes as the consortium scene).
const blockClass = (message: string) => /strict or non-read-only calls fail closed/.test(message) ? "UNAVAILABLE_FAIL_CLOSED"
  : /expired or has an invalid lifetime/.test(message) ? "SIGNED_CACHE_EXPIRED" : /previously revoked/.test(message) ? "LOCAL_REVOCATION_JOURNAL" : "OTHER";
const jsonLines = (text: string) => text.split(/\r?\n/).map((line) => { try { return JSON.parse(line); } catch { return undefined; } }).filter(Boolean);

const trust = JSON.parse(await readFile(join(stackDir, "gateway-trust.json"), "utf8"));
const { readerToken } = JSON.parse(await readFile(join(stackDir, "stack-local.json"), "utf8"));
const testnet = trust.chainId === 84532, rpcB = values.rpc ?? trust.rpcUrl;
const workDir = await mkdtemp(join(tmpdir(), "mcpshield-gateway-scene-"));
const sessions: { client: Client }[] = [];
let appB: Awaited<ReturnType<typeof buildApp>> | undefined, openedStoreB: ControlStore | undefined;

// The operator endpoint Gateway A is configured with. Cutting it is the outage; the operator stack itself keeps running.
let operatorDown = false;
const relay = createServer(async (request, response) => {
  if (operatorDown) { request.socket.destroy(); return; }
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  const headers = Object.fromEntries(Object.entries(request.headers)
    .filter(([key, value]) => typeof value === "string" && !["host", "connection", "content-length"].includes(key))) as Record<string, string>;
  try {
    const upstream = await fetch(`${trust.apiUrl.replace(/\/$/, "")}${request.url}`, { method: request.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined, redirect: "manual" });
    response.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
    response.end(Buffer.from(await upstream.arrayBuffer()));
  } catch { response.writeHead(502); response.end(); }
});

function gatewayChild(env: Record<string, string>, subcommand: "inspect" | "run", artifactDir: string) {
  return new Promise<{ exitCode: number | null; stdout: any[]; stderr: any[]; ms: number; failure?: string }>((done) => {
    const started = performance.now();
    const child = spawn(process.execPath, [gatewayEntry, subcommand, "--artifact", artifactDir, "--mode", "live"], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = "", stderr = "", settled = false;
    const finish = (value: { exitCode: number | null; failure?: string }) => {
      if (settled) return; settled = true; clearTimeout(timer);
      done({ ...value, ms: performance.now() - started, stdout: jsonLines(stdout), stderr: jsonLines(stderr) });
    };
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish({ exitCode: null, failure: "GATEWAY_CHILD_TIMEOUT" }); }, CHILD_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", () => finish({ exitCode: null, failure: "GATEWAY_SPAWN_FAILED" }));
    child.once("close", (exitCode) => finish({ exitCode }));
  });
}

async function inspect(env: Record<string, string>, artifactDir: string) {
  const result = await gatewayChild(env, "inspect", artifactDir);
  const decision = result.stdout.at(-1), path = result.stderr.find((event) => event.event === "admission_path");
  const failure = result.failure ?? result.stderr.find((event) => event.event === "gateway_error")?.message;
  return { decision: decision?.decision ?? "BLOCK", releaseStatus: decision?.releaseStatus ?? null, reasonCode: decision?.reasonCode ?? null,
    decisionSource: path?.decisionSource ?? null, ms: Math.round(result.ms), error: failure ? String(failure).slice(0, 160) : null };
}

async function runOnce(env: Record<string, string>, artifactDir: string) {
  // `run` spawns the artifact only when admitted. Exit 3 with a BLOCK decision = refused before spawn (gateway index.mjs main()).
  const result = await gatewayChild(env, "run", artifactDir);
  const blocked = [...result.stderr].reverse().find((event) => event.schemaVersion === "1.0.0" && event.decision === "BLOCK");
  return { exitCode: result.exitCode, releaseStatus: blocked?.releaseStatus ?? null, reasonCode: blocked?.reasonCode ?? null,
    refusedBeforeSpawn: result.exitCode === 3 && Boolean(blocked), ms: Math.round(result.ms), failure: result.failure ?? null };
}

async function session(command: string, args: string[], env: Record<string, string>, name: string) {
  const transport = new StdioClientTransport({ command, args, env, stderr: "pipe" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => { if (stderr.length < 1_000_000) stderr += chunk; });
  const client = new Client({ name, version: "1" });
  await client.connect(transport);
  const opened = { client, stderr: () => stderr };
  sessions.push(opened);
  return opened;
}

async function callOnce(target: Awaited<ReturnType<typeof session>>) {
  const started = performance.now(), mark = target.stderr().length;
  let timer: NodeJS.Timeout | undefined;
  try {
    const result: any = await Promise.race([target.client.callTool({ name: "list_messages", arguments: {} }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("CALL_TIMEOUT")), CALL_TIMEOUT_MS); })]);
    const ok = result?.isError !== true && JSON.parse(result.content[0].text).messages[0].subject === "Welcome";
    return { ok, ms: performance.now() - started, reasonCode: null as string | null };
  } catch {
    await sleep(100); // the Gateway writes its refusal to stderr before it closes the session
    // Only what this call wrote: an earlier refusal in the same session must not explain this failure.
    const blocked = jsonLines(target.stderr().slice(mark)).filter((event) => event.event === "gateway_runtime_blocked").at(-1);
    return { ok: false, ms: performance.now() - started, reasonCode: blocked ? blockClass(String(blocked.error ?? "")) : "CALL_FAILED" };
  } finally { clearTimeout(timer); }
}

const verdictLine = (who: string, version: string, result: Awaited<ReturnType<typeof inspect>>, via: string) => log(`${who}사 Gateway`,
  `mail-mcp ${version} → ${result.decision === "ALLOW" ? "실행 허용" : "실행 차단"} · ${STATUS[result.releaseStatus] ?? "상태 없음"}(${result.releaseStatus ?? "-"}, ${result.reasonCode ?? result.error ?? "-"}) · ${via} · ${seconds(result.ms)}`);

async function shutdown(exitCode: number) {
  for (const opened of sessions) await opened.client.close().catch(() => {});
  // appB.close() also closes B's store and chain reader. If B's app was never built, close the store here: an open
  // SQLite file keeps Windows from removing the temporary folder.
  if (appB) await appB.close().catch(() => {}); else await (async () => openedStoreB?.close())().catch(() => {});
  relay.close();
  await rm(workDir, { recursive: true, force: true }).catch(() => {});
  process.exit(exitCode);
}
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => void shutdown(130));

try {
  await new Promise<void>((done) => relay.listen(0, "127.0.0.1", done));
  const relayUrl = `http://127.0.0.1:${(relay.address() as any).port}`;

  // Company B: its own control API with its own tenant, credentials and admission key; the chain is its only source of status.
  const signing = generateKeyPairSync("ed25519"), tenantB = "company-b", keyIdB = "company-b-admission";
  const tokenB = { admin: randomBytes(24).toString("hex"), reader: randomBytes(24).toString("hex") };
  const storeB = openedStoreB = await ControlStore.open(join(workDir, "company-b.sqlite"));
  appB = await buildApp({ databasePath: ":memory:", adminApiToken: randomBytes(24).toString("hex"), scannerApiToken: randomBytes(24).toString("hex"), controlPlane: {
    store: storeB, credentials: [{ token: tokenB.admin, tenantId: tenantB, role: "admin" }, { token: tokenB.reader, tenantId: tenantB, role: "reader" }],
    artifactPath: join(workDir, "company-b-artifacts"), evidencePath: join(workDir, "company-b-evidence"), evidenceKey: randomBytes(32).toString("hex"),
    signingKey: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: keyIdB,
    // Same budget as the operator stack: a public RPC read from Korea takes 1.0-2.5 s (ADR-009).
    chainDecision: v2ChainReader({ rpcUrls: [rpcB], registryContract: trust.registryContract, chainId: trust.chainId, confirmations: testnet ? 2 : 1, timeoutMs: testnet ? 3000 : undefined }) } });
  await appB.listen({ host: "127.0.0.1", port: 0 });
  const urlB = `http://127.0.0.1:${(appB.server.address() as any).port}`, publicKeyB = signing.publicKey.export({ type: "spki", format: "pem" }).toString();

  console.log([
    "", `MCPShield 두 회사 Gateway 장면 · chain ${trust.chainId} · ReleaseRegistryV3 ${trust.registryContract}`,
    `  A사 Gateway → 운영사 API의 서명된 판정을 받습니다 (운영사 체인 RPC ${host(trust.rpcUrl)}).`,
    `  B사 Gateway → B사 자체 API만 믿습니다. 같은 바이트를 스스로 해석하고 체인을 직접 읽습니다 (RPC ${host(rpcB)}). 키도 거래도 없습니다.`,
    `  매 도구 호출마다 Gateway가 판정을 다시 받습니다(엄격 모드). 지연 표본 ${samples}회 · 결과 ${out}`, "",
  ].join("\n"));

  const operatorReleases = async () => {
    const response = await fetch(`${trust.apiUrl.replace(/\/$/, "")}/v1/releases`, { headers: { authorization: `Bearer ${readerToken}` } });
    if (!response.ok) throw new Error(`OPERATOR_API_HTTP_${response.status}`);
    return (await response.json()).items as any[];
  };
  const prepared: Record<string, { a: any; b: any; dirA: string; dirB: string }> = {};
  for (const version of ["1.0.0", "1.0.1"]) {
    // Company A downloads the package itself and finds the operator's record by the bytes' fingerprints.
    const dirA = join(workDir, "company-a", `mail-mcp-${version}`);
    await cp(join(repo, "demo/fixtures", `mail-mcp-${version}`), dirA, { recursive: true });
    const local = await resolveArtifact({ sourceType: "local", locator: dirA });
    const a = (await operatorReleases()).find((item) => item.artifactDigest === local.artifactDigest && item.toolSurfaceHash === local.toolSurfaceHash);
    if (!a) throw new Error(`OPERATOR_RELEASE_MISSING:${version}`);
    const response = await appB.inject({ method: "POST", url: "/v1/releases/resolve", headers: { authorization: `Bearer ${tokenB.admin}` }, payload: { sourceType: "fixture", locator: `mail-mcp-${version}` } });
    if (response.statusCode >= 300) throw new Error(`COMPANY_B_HTTP_${response.statusCode}`);
    const b = response.json().release, dirB = (await storeB.get(tenantB, "release", b.releaseId))!.artifactDir as string;
    log("B사", `mail-mcp ${version} 바이트를 직접 해석 · releaseId ${short(b.releaseId)} · 운영사 기록과 ${b.releaseId === a.releaseId ? "같음" : "다름"}`);
    prepared[version] = { a, b, dirA, dirB };
  }
  const gatewayEnv = (who: "A" | "B", version: string, extra: Record<string, string> = {}) => ({ ...getDefaultEnvironment(),
    MCPSHIELD_MODE: "live", MCPSHIELD_API_URL: who === "A" ? relayUrl : urlB, MCPSHIELD_POLICY_HASH: trust.policyHash,
    MCPSHIELD_CONTROL_RELEASE_ID: who === "A" ? prepared[version].a.releaseId : prepared[version].b.releaseId,
    MCPSHIELD_TENANT_ID: who === "A" ? trust.tenantId : tenantB, MCPSHIELD_CONTROL_TOKEN: who === "A" ? readerToken : tokenB.reader,
    MCPSHIELD_CACHE_PUBLIC_KEY: who === "A" ? trust.publicKey : publicKeyB, MCPSHIELD_CACHE_KEY_ID: who === "A" ? trust.keyId : keyIdB,
    MCPSHIELD_CHAIN_ID: String(trust.chainId), MCPSHIELD_REGISTRY_CONTRACT: trust.registryContract, MCPSHIELD_VALIDATOR_SET_VERSION: String(trust.validatorSetVersion),
    MCPSHIELD_ADMISSION_MODE: "strict", MCPSHIELD_ADMISSION_TIMEOUT_MS: "8000", MCPSHIELD_TELEMETRY_ENABLED: "false", ...extra }) as Record<string, string>;
  const dir = (who: "A" | "B", version: string) => who === "A" ? prepared[version].dirA : prepared[version].dirB;
  const report: any = { schemaVersion: "mcpshield.gateway-scene.v1", startedAt: new Date().toISOString(), chainId: trust.chainId, registryContract: trust.registryContract,
    rpcHosts: { operator: host(trust.rpcUrl), companyB: host(rpcB) }, method: "GATEWAY_CHILD_PROCESSES_AND_MCP_STDIO_SESSIONS",
    releases: Object.fromEntries(Object.entries(prepared).map(([version, entry]) => [version, { operatorReleaseId: entry.a.releaseId, companyBReleaseId: entry.b.releaseId, sameId: entry.a.releaseId === entry.b.releaseId }])) };

  const problems: string[] = []; // anything that does not go as the scene expects makes the exit code 1

  // Scene 1: the approved update. Each company checks on its own, then uses the tool; every call is checked again.
  log("장면 1", "승인된 업데이트 mail-mcp 1.0.0 · 두 회사가 각자 확인합니다");
  const safe = { A: await inspect(gatewayEnv("A", "1.0.0"), dir("A", "1.0.0")), B: await inspect(gatewayEnv("B", "1.0.0"), dir("B", "1.0.0")) };
  verdictLine("A", "1.0.0", safe.A, "운영사 API 판정"); verdictLine("B", "1.0.0", safe.B, "B사 API가 체인 직접 확인");
  report.safe = { inspect: safe };
  if (safe.A.decision === "ALLOW" && safe.B.decision === "ALLOW") {
    const targets = {
      direct: await session(process.execPath, [join(dir("A", "1.0.0"), "index.mjs")], getDefaultEnvironment(), "direct"),
      A: await session(process.execPath, [gatewayEntry, "stdio"], gatewayEnv("A", "1.0.0", { MCPSHIELD_ARTIFACT_DIR: dir("A", "1.0.0") }), "gateway-a"),
      B: await session(process.execPath, [gatewayEntry, "stdio"], gatewayEnv("B", "1.0.0", { MCPSHIELD_ARTIFACT_DIR: dir("B", "1.0.0") }), "gateway-b"),
    };
    const latency: Record<string, number[]> = { direct: [], A: [], B: [] };
    let failed = 0;
    // Interleaved so chain and RPC noise affect every target alike; the first rounds warm up connections.
    for (let index = 0; index < samples + WARM_UP; index++) for (const [name, target] of Object.entries(targets)) {
      const call = await callOnce(target);
      if (!call.ok) failed++; else if (index >= WARM_UP) latency[name].push(call.ms);
    }
    report.safe.latencyMs = { direct: summary(latency.direct), gatewayA: summary(latency.A), gatewayB: summary(latency.B), failedCalls: failed };
    const line = (name: string) => `p50 ${report.safe.latencyMs[name].p50} ms · p95 ${report.safe.latencyMs[name].p95} ms`;
    log("A사 Gateway", `list_messages 호출 ${latency.A.length}회 성공 · 호출마다 판정 재확인 포함 ${line("gatewayA")}`);
    log("B사 Gateway", `list_messages 호출 ${latency.B.length}회 성공 · 호출마다 판정 재확인 포함 ${line("gatewayB")}`);
    log("비교", `Gateway 없이 직접 호출 ${line("direct")} · 실패 ${failed}회`);

    if (failed) problems.push("LATENCY_CALLS_FAILED");

    // Scene 2: the operator goes away. A has no other source and stops; B never needed the operator. Fresh sessions, opened
    // while the operator still answers (each starts with its own admission check), so a session lost in scene 1 cannot pass
    // for the outage.
    log("장면 2", "운영사 서버 연결을 끊습니다");
    const fresh = {
      A: await session(process.execPath, [gatewayEntry, "stdio"], gatewayEnv("A", "1.0.0", { MCPSHIELD_ARTIFACT_DIR: dir("A", "1.0.0") }), "gateway-a-outage"),
      B: await session(process.execPath, [gatewayEntry, "stdio"], gatewayEnv("B", "1.0.0", { MCPSHIELD_ARTIFACT_DIR: dir("B", "1.0.0") }), "gateway-b-outage"),
    };
    operatorDown = true;
    const outage = { A: await callOnce(fresh.A), B: await callOnce(fresh.B) };
    operatorDown = false;
    log("A사 Gateway", outage.A.ok ? "계속 사용됨 (예상과 다름)" : `도구 호출 차단 · 판정을 받을 수 없으면 멈추는 엄격 모드(${outage.A.reasonCode})`);
    log("B사 Gateway", outage.B.ok ? `계속 사용 · 자기 API가 체인을 직접 확인 · ${Math.round(outage.B.ms)} ms` : `도구 호출 실패 (${outage.B.reasonCode})`);
    report.outage = { gatewayA: { ok: outage.A.ok, reasonCode: outage.A.reasonCode }, gatewayB: { ok: outage.B.ok, reasonCode: outage.B.reasonCode, ms: Math.round(outage.B.ms) } };
    if (outage.A.ok) problems.push("OUTAGE_A_NOT_BLOCKED");
    if (!outage.B.ok) problems.push("OUTAGE_B_STOPPED");
  } else { log("장면 1", "한 회사 이상이 차단해 도구 호출과 운영사 장애 장면은 건너뜁니다"); problems.push("SAFE_RELEASE_NOT_ALLOWED"); }

  // Scene 3: the malicious update. `run` is tried only once inspect already saw a terminal or held status, so the
  // malicious fixture is never started by this scene.
  log("장면 3", "악성 업데이트 mail-mcp 1.0.1 · 두 회사가 실행을 시도합니다");
  const bad = { A: await inspect(gatewayEnv("A", "1.0.1"), dir("A", "1.0.1")), B: await inspect(gatewayEnv("B", "1.0.1"), dir("B", "1.0.1")) };
  report.malicious = { inspect: bad, run: {} };
  for (const who of ["A", "B"] as const) {
    if (!["REVOKED", "QUARANTINED"].includes(bad[who].releaseStatus)) { verdictLine(who, "1.0.1", bad[who], "run은 시도하지 않음"); problems.push(`MALICIOUS_${who}_NOT_REVOKED`); continue; }
    const run = report.malicious.run[who] = await runOnce(gatewayEnv(who, "1.0.1"), dir(who, "1.0.1"));
    if (!run.refusedBeforeSpawn) problems.push(`MALICIOUS_${who}_NOT_REFUSED`);
    log(`${who}사 Gateway`, `mail-mcp 1.0.1 실행 시도 → ${run.refusedBeforeSpawn ? "프로세스를 띄우기 전에 거부" : "거부 확인 실패"} · ${STATUS[run.releaseStatus] ?? "상태 없음"}(${run.releaseStatus ?? "-"}) · exit ${run.exitCode} · ${seconds(run.ms)}`);
  }

  report.problems = problems;
  report.finishedAt = new Date().toISOString();
  await writeFile(out, `${JSON.stringify(report, null, 2)}\n`);
  log("점검", problems.length ? `기대와 다름 · ${problems.join(", ")}` : "세 장면 모두 기대대로입니다");
  log("기록", `결과를 ${out} 에 저장했습니다`);
  await shutdown(problems.length ? 1 : 0);
} catch (error: any) {
  log("장면", `실패 · ${/^[A-Z][A-Z0-9_:.]{2,80}$/.test(error?.message ?? "") ? error.message : "UNEXPECTED_ERROR"}`);
  await shutdown(1);
}
