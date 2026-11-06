// Key-rotation rehearsal on a local chain for the mentoring Q&A: runs contracts/scripts/rotation-rehearsal.ts, prints a
// short summary per scenario and writes the measured JSON.
//   node --import tsx scripts/demo/key-rotation-rehearsal.mts [--releases 2] [--out <file>]
// In-process Ganache only: no RPC, no key files, no network. Exits 1 when any expectation fails.
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { runRotationRehearsal } from "../../contracts/scripts/rotation-rehearsal.js";

const repo = resolve(import.meta.dirname, "../..");
const DEFAULT_OUT = "benchmarks/results/key-rotation-rehearsal-2026-11-03/result.json";
const n = (value: number) => value.toLocaleString("en-US");
const span = (seconds: number) => seconds >= 3600 ? `${(seconds / 3600).toFixed(2)}시간(${n(seconds)}초)` : `${n(seconds)}초`;
const range = (s: { min: number; max: number }) => s.min === s.max ? n(s.min) : `${n(s.min)}~${n(s.max)}`;
type Cost = { resignatures: number; resignaturesPerRelease: number; blockedSeconds: number; blockedWindows: unknown[]; gatewayPinChangesPerCompany: number };
const cost = (s: Cost) => `재서명 ${s.resignatures}건(릴리스당 ${s.resignaturesPerRelease}) · 차단 ${span(s.blockedSeconds)}`
  + `${s.blockedWindows.length > 1 ? `(${s.blockedWindows.length}구간)` : ""} · Gateway 버전 설정 변경 회사당 ${s.gatewayPinChangesPerCompany}회`;

try {
  const { values } = parseArgs({ options: { releases: { type: "string", default: "2" }, out: { type: "string" } } });
  const out = values.out ? resolve(values.out) : resolve(repo, DEFAULT_OUT);
  const started = performance.now();
  const result = await runRotationRehearsal({ liveReleases: Number(values.releases) });
  const wallClockMs = Math.round(performance.now() - started);
  const { S1, S2, S3 } = result.scenarios, { gas } = result;
  const { withInterimReapproval: S2a, withoutInterimReapproval: S2b } = S2.caughtBeforeUse;
  const { withInterimReapproval: S2c, withoutInterimReapproval: S2d } = S2.caughtAfterQuarantine;
  console.log([
    `키 교체 리허설: 로컬 Ganache(${result.chain.hardfork}), 시나리오마다 새 체인, 시간 이동만 사용, 활성 릴리스 ${result.liveReleases}개`,
    `S1 정상 교체(C→C'): ${cost(S1)}`,
    `   교체 대기 ${span(S1.timelockSeconds)} 동안 버전과 VERIFIED 유지 · 옛 버전 서명 ${S1.reverts.staleVote} · 빠진 키 C ${S1.reverts.removedKeyVote}`,
    `   gas: 교체 예약 ${n(S1.gas.scheduleRotation)} · 교체 실행 ${n(S1.gas.rotate)} · 재서명 1건 ${range(S1.resignatureGas)}`,
    `S2 키 유출(C 즉시 비활성화, ${span(S2a.timelockSeconds)} 뒤 C'로 교체): 비활성화된 C의 서명 ${S2a.reverts.leakedKeyVote} · 격리 ${S2a.reverts.leakedKeyQuarantine}`,
    `   C를 쓰기 전에 알아챔, 중간 재승인 함:   ${cost(S2a)}`,
    `   C를 쓰기 전에 알아챔, 중간 재승인 안 함: ${cost(S2b)}`,
    `   남은 A·B 중 하나가 ABSTAIN: 라운드 ${S2a.abstainProbe?.round.outcome}, 릴리스 ${S2a.abstainProbe?.status} → 새 라운드에 서명 ${S2a.abstainProbe?.extraSignatures}건 더`,
    `   C가 먼저 모든 릴리스를 ${span(S2c.quarantine!.seconds)} 격리한 뒤 알아챔(비활성화도 재승인도 격리를 풀지 못함):`,
    `      중간 재승인 함:   ${cost(S2c)}`,
    `      중간 재승인 안 함: ${cost(S2d)}`,
    `   gas: 비활성화 ${n(S2a.gas.disable)} · C의 격리 ${range(gas.quarantine)}`,
    `S3 두 키(B·C) 비활성화: A 혼자 낸 PASS ${S3.votesThatCouldNotDecide}건은 결정 못 함 · ${cost(S3)}`,
    `   gas: 비활성화 ${S3.gas.disable.map(n).join(" / ")} · 교체 실행(두 키 교체) ${n(S3.gas.rotate)}`,
    `gas: 교체 예약은 등록소의 첫 예약 ${range(gas.scheduleRotationFirst)} · 교체를 한 번 거친 뒤 ${n(gas.scheduleRotationAfterRotation)}`,
    `   비활성화는 키 자리 0/1/2에 따라 ${[gas.disableBySlot.slot0, gas.disableBySlot.slot1, gas.disableBySlot.slot2].map(n).join(" / ")}`,
    `   새 정책 게시 ${n(gas.policyPublish)} · 폐기 ${n(gas.policyDeprecate)} (별도 정책, 시나리오 정책과 VERIFIED는 그대로)`,
    `   하루 재승인(같은 버전의 새 라운드): 여는 표 ${n(gas.dailyRenewal.opensRound)} · 결정 표 ${n(gas.dailyRenewal.decides)} · 결정 뒤 표 ${n(gas.dailyRenewal.afterDecision)}`
      + ` (2표 ${n(gas.dailyRenewal.twoVotes)}, 3표 ${n(gas.dailyRenewal.threeVotes)}) · C의 첫 표였던 첫 재승인의 결정 뒤 표 ${n(gas.firstRenewalAfterDecision)}`,
    `확인 ${result.assertedChecks}건 통과 · 실제 걸린 시간 ${(wallClockMs / 1000).toFixed(1)}초`,
  ].join("\n"));
  await mkdir(dirname(out), { recursive: true });
  const run = { command: `node --import tsx scripts/demo/key-rotation-rehearsal.mts --releases ${result.liveReleases}`, generatedAt: new Date().toISOString(), wallClockMs };
  await writeFile(out, `${JSON.stringify({ ...result, run }, null, 2)}\n`);
  console.log(`결과: ${relative(process.cwd(), out)}`);
} catch (error: any) {
  console.error(`리허설 실패: ${error?.message ?? error}`);
  process.exitCode = 1;
}
