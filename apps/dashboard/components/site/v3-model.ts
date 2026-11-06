// Pure view model for the Figma scan screens on the V3 operator API (ADR-008). No React and no fetch here:
// every label below is derived only from what the API returned, and no step is marked done before the data says so.
import type { Admission, ChainAction, Release, Scan, V3Round, V3Vote, V3Votes } from "../release-workflow";

export type Lane = "A" | "B" | "C";
export const LANES = ["A", "B", "C"] as const;
/** Role names the team runs (SINGLE_INSTITUTION_DEMO). A role never claims an AI witness: whether a vote had one is read from
 *  that vote's own evidence (witnessText). C is the validator the stack lets send the emergency quarantine. */
export const LANE_ROLE: Record<Lane, string> = { A: "규칙·시험 환경 검사", B: "규칙·시험 환경 검사", C: "규칙·시험 환경 검사 · 긴급 격리 담당" };
export const TEAM_RUN_NOTE = "시연 구성: 검증자 A·B·C의 키와 프로세스는 팀이 운영합니다 (SINGLE_INSTITUTION_DEMO). 각자 따로 검사·서명하는 규칙을 보여 줄 뿐, 독립 기관 검사의 증거는 아닙니다.";
export const AI_WITNESS_NOTE = "AI는 증인일 뿐입니다. 의심이나 무응답은 PASS를 보류로만 바꾸고, 승인·폐기는 하지 못합니다.";
export type StepState = "pending" | "running" | "done" | "failed";
export type Tone = "pass" | "fail" | "review" | "neutral";
export type HistoryItem = { eventName: string; createdAt: string; payload: any };

// FAIL is a vote ("불합격"); "실패" stays for errors only.
const VERDICT_KO: Record<string, string> = { PASS: "통과", FAIL: "불합격", ABSTAIN: "보류" };
const OUTCOME_KO: Record<string, string> = { OPEN: "투표 중 · 결론 전", APPROVED: "승인 · 2/3 PASS 달성", REJECTED: "폐기 · 2/3 FAIL 달성", SPLIT: "표가 갈림 · 사람 검토" };
export const STATUS_KO: Record<string, string> = { VERIFIED: "승인됨", REVOKED: "폐기됨", QUARANTINED: "긴급 격리 중", UNVERIFIED: "승인 전", EXPIRED: "승인 만료" };
export const statusKo = (status?: string | null) => status ? STATUS_KO[status] ?? status : "기록 없음";
export const outcomeKo = (outcome?: string | null) => outcome ? OUTCOME_KO[outcome] ?? outcome : "기록 없음";
export const verdictKo = (verdict?: string | null) => verdict ? VERDICT_KO[verdict] ?? verdict : "—";
export const outcomeTone = (outcome?: string | null): Tone => outcome === "APPROVED" ? "pass" : outcome === "REJECTED" ? "fail" : outcome === "SPLIT" ? "review" : "neutral";
const SEVERITY_LEVEL: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const DECIDED = new Set(["APPROVED", "REJECTED", "SPLIT"]);
const DECIDED_STATUS = new Set(["VERIFIED", "REVOKED", "QUARANTINED", "EXPIRED"]);

export const short = (h?: string | null) => h ? `${h.slice(0, 10)}…${h.slice(-4)}` : "없음";
/** Tool name of a release from its own legacy id ("mail-mcp@1.0.0" → "mail-mcp"); never a fixed name. */
export const toolName = (release?: Pick<Release, "legacyReleaseId"> | null) => release?.legacyReleaseId ? release.legacyReleaseId.split("@")[0] || "—" : "—";

const pad = (value: number) => String(value).padStart(2, "0");
const NBSP = " ";
/** "11.03 23:51" in the viewer's time zone; the date and the time never break apart. */
export function when(value?: number | string | null) {
  if (value === null || value === undefined || value === "") return "—";
  const ms = typeof value === "number" ? value * 1000 : Date.parse(value);
  if (!Number.isFinite(ms)) return "—";
  const date = new Date(ms);
  return `${pad(date.getMonth() + 1)}.${pad(date.getDate())}${NBSP}${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
/** "23:51:34" (24 h). */
export function clock(value?: number | string | null) {
  const ms = typeof value === "number" ? value : typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isFinite(ms)) return "—";
  const date = new Date(ms);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function ago(iso: string, now = Date.now()) {
  const seconds = Math.max(0, (now - Date.parse(iso)) / 1000);
  if (seconds < 60) return "방금 전";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}분 전`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}시간 전`;
  return new Date(iso).toLocaleDateString("ko-KR");
}

/** The chain is named from the data's chainId only: local Ganache is never called a testnet, and Base Sepolia always is. */
export function chainLabel(id?: number | null) {
  if (id === 31337) return "로컬 Ganache · chain 31337";
  if (id === 84532) return "Base Sepolia 테스트넷 · chain 84532";
  if (typeof id === "number" && Number.isSafeInteger(id)) return `chain ${id}`;
  return "체인 확인 전";
}
/** Only a Base Sepolia transaction gets an explorer link; anything else is shown as text. */
export const txHref = (id: number | null | undefined, h?: string | null) => id === 84532 && typeof h === "string" && /^0x[0-9a-f]{64}$/i.test(h) ? `https://sepolia.basescan.org/tx/${h}` : null;

export function chainIdOf({ release, actions, admission }: { release?: Release | null; actions?: ChainAction[] | null; admission?: Admission | null }) {
  return release?.chain?.chainId ?? actions?.[0]?.chainId ?? admission?.snapshot?.chainId ?? null;
}

export type ChainState = { status: string | null; text: string; failed: boolean };
/**
 * The release state a screen may show: the chain view when it was read. After a failed chain read nothing is shown as a state
 * (never the database copy, never UNVERIFIED and never an approval); the indexer's copy only when the chain was readable.
 */
export function chainState({ votes, release, error }: { votes?: V3Votes | null; release?: Release | null; error?: string | null }): ChainState {
  if (error) return { status: null, text: "체인 조회 실패 · 상태 미확인 (승인으로 간주하지 않음)", failed: true };
  if (votes?.status) return { status: votes.status, text: statusKo(votes.status), failed: false };
  if (votes && !votes.registered) return { status: null, text: "체인에 미등록", failed: false };
  if (release?.chainUnavailable) return { status: null, text: "체인 조회 불가 · 상태 미확인 (승인으로 간주하지 않음)", failed: true };
  if (votes && release?.status) return { status: release.status, text: statusKo(release.status), failed: false };
  return { status: null, text: "불러오는 중", failed: false };
}
/** Whether the chain has a conclusion worth an admission lookup (no automatic lookup before that: each one is an audit event). */
export const decidedOnChain = (status?: string | null, round?: V3Round) => Boolean(status && DECIDED_STATUS.has(status)) || Boolean(round && DECIDED.has(round.outcome));

/** Registry order: validators[0..2] are lanes A, B, C (same rule as lib/ledger-v3.ts). */
export function laneOf(votes: Pick<V3Votes, "validators"> | null | undefined, address?: string | null): Lane | null {
  if (!address) return null;
  const index = (votes?.validators ?? []).findIndex((item) => item.toLowerCase() === address.toLowerCase());
  return index >= 0 && index < 3 ? LANES[index] : null;
}

export function shownRound(votes: V3Votes | null | undefined, scanId?: string | null): V3Round | undefined {
  const rounds = votes?.rounds ?? [];
  if (scanId) return rounds.find((round) => round.scanId === scanId);
  return rounds.find((round) => round.roundId === votes?.decisionRound) ?? rounds.find((round) => round.live) ?? rounds[0];
}

const sameHex = (a?: string | null, b?: string | null) => Boolean(a && b && a.toLowerCase() === b.toLowerCase());
const voteOf = (round: V3Round | undefined, address?: string | null) => round?.votes.find((vote) => sameHex(vote.validator, address));
const uniqueCodes = (findings: { code: string }[]) => [...new Set(findings.map((finding) => finding.code))];
const isRule = (finding: { stage: string; deterministic: boolean }) => finding.deterministic === true && finding.stage !== "AI";
const blocking = (severity: string) => severity === "HIGH" || severity === "CRITICAL";
/** The scanner keeps a model's findings only when the model answered; otherwise its stage-AI finding is the local semantic rule. */
export const witnessed = (vote?: V3Vote | null) => vote?.evidence?.ai?.status === "COMPLETED";

export type Witness = { label: string; model?: string | null; note?: string; tone: Tone; state: "unknown" | "none" | "answered" | "silent" | "waiting" };
/** The validator's own AI witness, from its signed evidence summary. A witness only ever holds a PASS; it never approves or revokes,
 *  so it is never shown in the PASS colour. */
export function witnessText(vote?: V3Vote | null): Witness {
  if (!vote?.cast) return { label: "투표 후 표시", tone: "neutral", state: "waiting" };
  if (vote.evidence === null) return { label: "확인 불가 · 증거 요약 없음", tone: "neutral", state: "unknown" };
  const ai = vote.evidence.ai;
  if (ai === undefined) return { label: "확인 불가 · 이전 API 기록", tone: "neutral", state: "unknown" };
  if (ai === null) return { label: "없음 · 규칙·시험 환경만", tone: "neutral", state: "none" };
  const basis = vote.evidence.basis;
  if (ai.status === "COMPLETED") {
    const suspicions = vote.evidence.findings.filter((finding) => finding.stage === "AI");
    const held = vote.verdict === "ABSTAIN" && suspicions.some((finding) => blocking(finding.severity) && basis.includes(finding.code));
    const count = uniqueCodes(suspicions).length;
    return { label: count ? `응답함 · 의심 ${count}건` : "응답함 · 의심 없음", model: ai.model ?? "모델 미상", tone: held ? "review" : "neutral", state: "answered",
      note: held ? "AI 의심 → PASS 대신 보류 (판정 권한 없음)" : undefined };
  }
  return { label: "응답 없음", model: ai.model ?? "모델 미상", tone: "review", state: "silent", note: basis.includes("AI_UNAVAILABLE") ? "PASS 대신 보류 (AI_UNAVAILABLE)" : undefined };
}

/** tx.label "중계": the hash is the operator's completed relay of this signed vote, not yet seen by the indexer (same width as "거래"). */
export type Cell = { state: StepState; tone: Tone; title: string; lines: string[]; tx?: { hash: string; href: string | null; label?: string } | null };
export type LaneView = { lane: Lane; role: string; address: string | null; vote: V3Vote | undefined; voteKey: "PASS" | "FAIL" | "ABSTAIN" | "NONE";
  rescan: Cell; witness: Witness; signed: Cell; quarantine: Cell };

const eventFor = (history: HistoryItem[], name: string, scanId: string | null | undefined, address: string | null) =>
  Boolean(scanId) && history.some((item) => item.eventName === name && item.payload?.scanId === scanId && sameHex(item.payload?.validator, address));
const toneOfVerdict = (verdict?: string | null): Tone => verdict === "PASS" ? "pass" : verdict === "FAIL" ? "fail" : verdict === "ABSTAIN" ? "review" : "neutral";

export function laneViews({ votes, round, scanId, history = [], chainId = null }: { votes: V3Votes | null | undefined; round: V3Round | undefined; scanId?: string | null; history?: HistoryItem[]; chainId?: number | null }): LaneView[] {
  const roundScan = round?.scanId ?? scanId ?? null;
  return LANES.map((lane, index) => {
    const address = votes?.validators?.[index] ?? null;
    const vote = voteOf(round, address);
    const relayed = eventFor(history, "validator.vote.received", roundScan, address);
    const announced = eventFor(history, "validator.round.announced", roundScan, address);
    let rescan: Cell;
    if (vote?.cast) {
      const basis = vote.evidence?.basis ?? [];
      const title = vote.verdict === "PASS" ? (basis.length ? `PASS · 근거 ${basis.join(", ")}` : "차단 근거 없음")
        : vote.verdict === "FAIL" ? `FAIL 근거 ${basis.length || "?"}건` : `보류 사유 ${basis.length ? basis.join(", ") : "기록 없음"}`;
      const findings = vote.evidence?.findings ?? [];
      const rules = uniqueCodes(findings.filter(isRule)).length, signals = uniqueCodes(findings.filter((finding) => !isRule(finding))).length;
      rescan = { state: "done", tone: toneOfVerdict(vote.verdict), title: vote.evidence ? title : `${vote.verdict} · 증거 요약 없음`,
        lines: vote.evidence ? [`규칙 근거 ${rules}건`, `의심 신호 ${signals}건`] : ["증거 요약 없음 · 해시만 체인에 있음"] };
    } else if (relayed) rescan = { state: "done", tone: "neutral", title: "검사 완료 · 표 중계 접수", lines: [] };
    else if (announced) rescan = { state: "running", tone: "neutral", title: "자기 사본 검사 중", lines: [] };
    else rescan = { state: "pending", tone: "neutral", title: "대기", lines: [] };
    let signed: Cell;
    if (vote?.cast && vote.verdict) {
      signed = { state: "done", tone: toneOfVerdict(vote.verdict), title: `${vote.verdict} · ${verdictKo(vote.verdict)}`,
        lines: [`증거 ${short(vote.evidenceHash)}`, ...(vote.txHash ? [] : ["거래 해시 확인 중"]), ...(vote.afterDecision ? ["결론 뒤 기록 · 결과 불변"] : [])],
        tx: vote.txHash ? { hash: vote.txHash, href: txHref(chainId, vote.txHash), ...(vote.txSource === "OPERATOR_RELAY" ? { label: "중계" } : {}) } : null };
    } else if (relayed) signed = { state: "running", tone: "neutral", title: "중계 접수 · 체인 기록 대기", lines: [] };
    else signed = { state: "pending", tone: "neutral", title: "아직 투표 안 함", lines: [] };
    // A quarantine and the vote it comes with are backed by the same evidence file, so the evidenceHash ties a quarantine to this
    // round. Before this validator's vote lands, a quarantine counts for this round unless it is backed by its vote in another round.
    const elsewhere = new Set((votes?.rounds ?? []).filter((item) => item.roundId !== round?.roundId)
      .flatMap((item) => item.votes.filter((other) => other.cast && other.evidenceHash && sameHex(other.validator, address)).map((other) => other.evidenceHash!.toLowerCase())));
    const record = votes?.quarantines?.find((item) => sameHex(item.validator, address)
      && (vote?.cast ? sameHex(item.evidenceHash, vote.evidenceHash) : !elsewhere.has(item.evidenceHash.toLowerCase())));
    const revokedNote = votes?.status === "REVOKED" ? ["폐기가 격리보다 우선"] : [];
    // "격리 안 함" needs evidence. With the registry read: this validator never used its one quarantine on this release, or the
    // quarantine it used is tied by evidence to its vote in another round. A quarantine is not tied to a round on chain, so an indexed
    // vote alone never says it. Without the registry read (an older API), an indexed vote keeps the earlier rule.
    const used = address !== null ? votes?.quarantineUsedAt?.[address.toLowerCase()] : undefined;
    const own = votes?.quarantines?.filter((item) => sameHex(item.validator, address)) ?? [];
    const unmatched = own.find((item) => !elsewhere.has(item.evidenceHash.toLowerCase()));
    // An indexed quarantine of this validator that no other round's vote accounts for always wins over a 0 read (reads of one view can
    // come from RPC backends at different heights).
    const none = used === undefined ? Boolean(vote?.txHash) && vote?.txSource !== "OPERATOR_RELAY" : !unmatched && (used === 0 || own.length > 0);
    let quarantine: Cell;
    if (record) quarantine = { state: "done", tone: "fail", title: `긴급 격리 실행 · ${record.reason ?? "사유 미상"}`, lines: [`만료 ${when(record.expiresAt)}`, ...revokedNote],
      tx: { hash: record.txHash, href: txHref(chainId, record.txHash) } };
    else if (vote?.cast && none) quarantine = { state: "done", tone: "neutral", title: "격리 안 함", lines: [] };
    else if (vote?.cast && unmatched) quarantine = { state: "done", tone: "fail", title: `긴급 격리 기록 · ${unmatched.reason ?? "사유 미상"}`,
      lines: ["이 표와 다른 증거로 기록됨", `만료 ${when(unmatched.expiresAt)}`, ...revokedNote], tx: { hash: unmatched.txHash, href: txHref(chainId, unmatched.txHash) } };
    else if (vote?.cast) quarantine = { state: "running", tone: "neutral", title: "격리 기록 확인 중", lines: ["인덱서 관측 전"] };
    else quarantine = { state: "pending", tone: "neutral", title: "대기", lines: [] };
    return { lane, role: LANE_ROLE[lane], address, vote, voteKey: vote?.cast && vote.verdict ? vote.verdict : "NONE", rescan, witness: witnessText(vote), signed, quarantine };
  });
}

export type Step = { key: "register" | "announce" | "lanes" | "decision" | "gateway"; index: string; name: string; caption: string; state: StepState; tone: Tone; title: string; lines: string[];
  tx?: { hash: string; href: string | null } | null };
export type FlowView = { steps: Step[]; lanes: LaneView[]; done: number; outcome: string | null; gateway: "ALLOW" | "BLOCK" | null; chainId: number | null; status: string | null };

export function flowView({ release, scan, votes, round, history = [], actions = [], admission, admissionPending = false, votesError = null }: {
  release?: Release | null; scan?: Scan | null; votes?: V3Votes | null; round?: V3Round; history?: HistoryItem[]; actions?: ChainAction[]; admission?: Admission | null; admissionPending?: boolean; votesError?: string | null;
}): FlowView {
  const chainId = chainIdOf({ release, actions, admission });
  const releaseId = release?.releaseId ?? votes?.releaseId;
  const register = actions.find((item) => item.kind === "REGISTER_RELEASE" && item.releaseId === releaseId);
  const registeredEvent = history.find((item) => item.eventName === "chain.ReleaseRegistered");
  const registerTx = register?.txHash ?? registeredEvent?.payload?.txHash ?? null;
  let step1: Step;
  const base1 = { key: "register" as const, index: "01", name: "릴리스 등록", caption: "운영사 · 정확한 바이트의 해시를 체인에 고정" };
  if (votes?.registered || registeredEvent) step1 = { ...base1, state: "done", tone: "pass", title: "체인 등록됨",
    lines: [`artifact ${short(release?.artifactDigest)}`, `manifest ${short(release?.manifestDigest)}`, `tool surface ${short(release?.toolSurfaceHash)}`],
    tx: registerTx ? { hash: registerTx, href: txHref(chainId, registerTx) } : null };
  else if (register && ["FAILED", "DEAD_LETTER"].includes(register.status)) step1 = { ...base1, state: "failed", tone: "fail", title: `등록 실패 · ${register.errorCode ?? register.status}`, lines: [] };
  else if (register) step1 = { ...base1, state: "running", tone: "neutral", title: `등록 거래 전송 중 · ${register.status}`, lines: [] };
  else if (votesError) step1 = { ...base1, state: "pending", tone: "review", title: "체인 조회 실패 · 확인 전", lines: [] };
  else step1 = { ...base1, state: "pending", tone: "neutral", title: "미등록", lines: [] };

  const base2 = { key: "announce" as const, index: "02", name: "라운드 공지", caption: "운영사 검사 · 판정 권한 없음" };
  let step2: Step;
  const lastError = (scan?.lastError ?? null) as { code?: string } | null;
  if (scan?.status === "QUEUED" || scan?.status === "RUNNING") step2 = { ...base2, state: "running", tone: "neutral", title: "운영사 검사 중 · 라운드 준비", lines: [] };
  else if (scan?.status === "DEAD_LETTER") step2 = { ...base2, state: "failed", tone: "fail", title: `운영사 검사 실패 · ${lastError?.code ?? "원인 미상"}`, lines: [] };
  else if (scan?.status === "COMPLETED") {
    const result = scan.result as (Scan["result"] & { validFrom?: string }) | undefined;
    step2 = { ...base2, state: "done", tone: "neutral", title: "라운드 공지됨", lines: [`유효기간 ${when(result?.validFrom)} ~ ${when(result?.validUntil)}`, `운영사 참고 권고 ${result?.verdict ?? "없음"} · 판정 권한 없음`] };
  } else if (round) step2 = { ...base2, state: "done", tone: "neutral", title: "라운드 열림", lines: [`유효기간 ${when(round.validFrom)} ~ ${when(round.validUntil)}`, "운영사 검사 기록 없음 (다른 경로로 열린 라운드)"] };
  else step2 = { ...base2, state: "pending", tone: "neutral", title: "검사 요청 전", lines: [] };

  const lanes = laneViews({ votes, round, scanId: scan?.scanId, history, chainId });
  const cast = round?.votes.filter((vote) => vote.cast).length ?? 0;
  const anyActivity = lanes.some((lane) => lane.rescan.state !== "pending" || lane.signed.state !== "pending");
  const step3: Step = { key: "lanes", index: "03", name: "검증자 A·B·C", caption: "각자 재검사 · 자기 서명 · 운영사는 중계만",
    state: cast >= 3 ? "done" : anyActivity ? "running" : "pending", tone: "neutral", title: `${cast}/3 표 체인 기록`, lines: [] };

  const base4 = { key: "decision" as const, index: "04", name: "2-of-3 판정", caption: "체인 · ReleaseRegistryV3" };
  let step4: Step;
  if (!round) step4 = { ...base4, state: "pending", tone: "neutral", title: scan?.status === "COMPLETED" ? "첫 표 대기 · 0/3" : "라운드 열리기 전", lines: [] };
  else if (round.outcome === "OPEN") step4 = { ...base4, state: "running", tone: "neutral", title: `투표 중 · PASS ${round.approvals} · FAIL ${round.rejections} · 보류 ${round.abstentions}`,
    lines: votes?.status === "VERIFIED" ? ["이전 승인 유지 중 (VERIFIED)"] : [] };
  else if (round.outcome === "APPROVED") step4 = { ...base4, state: "done", tone: "pass", title: "승인 · 2/3 PASS 달성",
    lines: [`현재 상태 ${votes?.status ?? "—"}`, `승인 유효기간 ~ ${when(round.validUntil)} · 그 뒤 다시 검사`] };
  else if (round.outcome === "REJECTED") step4 = { ...base4, state: "done", tone: "fail", title: "폐기 · 2/3 FAIL 달성", lines: ["영구 폐기 · 같은 바이트 재등록 불가"] };
  else if (round.outcome === "SPLIT") step4 = { ...base4, state: "done", tone: "review", title: "표가 갈림 · 사람 검토", lines: ["사람 검토 전까지 실행 차단"] };
  else step4 = { ...base4, state: "running", tone: "neutral", title: round.outcome, lines: [] };

  const base5 = { key: "gateway" as const, index: "05", name: "Gateway 실행 판정", caption: "VERIFIED만 허용" };
  const decided = Boolean(round && DECIDED.has(round.outcome));
  const note = admission ? [`API 조회 ${when(admission.checkedAt)}`, "이 화면은 도구를 실행하지 않습니다"] : ["이 화면은 도구를 실행하지 않습니다"];
  let step5: Step;
  if (!decided) step5 = { ...base5, state: "pending", tone: "neutral", title: "결론 후 조회", lines: note };
  else if (!admission) step5 = { ...base5, state: "running", tone: "neutral", title: "실행 판정 조회 중", lines: note };
  else if (admissionPending) step5 = { ...base5, state: "running", tone: "neutral", title: "Gateway 판정 확인 중 (체인 확정 대기)", lines: note };
  else if (admission.decision === "ALLOW") step5 = { ...base5, state: "done", tone: "pass", title: `ALLOW · ${admission.reasonCode}`, lines: note };
  else step5 = { ...base5, state: "done", tone: "fail", title: `BLOCK · ${admission.reasonCode}`, lines: note };

  const steps = [step1, step2, step3, step4, step5];
  return { steps, lanes, done: steps.filter((step) => step.state === "done").length, outcome: round?.outcome ?? null,
    gateway: decided && admission && !admissionPending ? (admission.decision === "ALLOW" ? "ALLOW" : "BLOCK") : null, chainId,
    status: chainState({ votes, release, error: votesError }).status };
}

export type Card = { label: string; value: string; lines: string[]; tone: Tone; bar?: number };

export function verdictCard({ votes, release, admission, loading = false, votesError = null }: { votes?: V3Votes | null; release?: Release | null; admission?: Admission | null; loading?: boolean; votesError?: string | null }): Card {
  const state = chainState({ votes, release, error: votesError }), status = state.status;
  const live = votes?.rounds.find((round) => round.live);
  const quarantine = votes?.quarantines?.find((item) => item.expiresAt === votes.quarantineUntil) ?? votes?.quarantines?.[0];
  const first = status === "VERIFIED" ? `승인됨 · ${when(live?.validUntil ?? release?.validUntil)}까지 유효, 그 뒤 다시 검사`
    : status === "REVOKED" ? "폐기됨 · 영구 (같은 바이트 재등록 불가)"
    : status === "QUARANTINED" ? `긴급 격리 중 · ${when(votes?.quarantineUntil)}까지 · 검증자 ${laneOf(votes, quarantine?.validator) ?? "확인 중"}`
    : status === "UNVERIFIED" && votes?.needsReview ? "표가 갈림 · 사람 검토 전까지 실행 차단"
    : status === "UNVERIFIED" ? "아직 승인되지 않음 · 실행 차단"
    : status === "EXPIRED" ? "승인 만료 · 새 검사 필요" : state.text;
  const second = admission ? `Gateway ${admission.decision} · ${admission.reasonCode}` : "Gateway 판정 조회 전";
  const tone: Tone = loading || !status ? (state.failed ? "review" : "neutral") : status === "VERIFIED" && admission?.decision === "ALLOW" ? "pass" : status === "REVOKED" || status === "QUARANTINED" ? "fail" : "review";
  return { label: "현재 체인 상태", value: status ?? "—", lines: [first, second], tone };
}

export function consensusCard(round?: V3Round): Card {
  if (!round) return { label: "검증자 합의", value: "—", lines: ["라운드 기록 없음"], tone: "neutral" };
  const cast = round.votes.filter((vote) => vote.cast).length, late = round.votes.filter((vote) => vote.cast && vote.afterDecision).length;
  const value = round.outcome === "APPROVED" ? `${round.approvals}/3 PASS` : round.outcome === "REJECTED" ? `${round.rejections}/3 FAIL`
    : round.outcome === "SPLIT" ? `PASS ${round.approvals} · FAIL ${round.rejections} · 보류 ${round.abstentions}` : `${cast}/3 투표`;
  const line = `${outcomeKo(round.outcome)}${late ? ` · 결론 뒤 ${late}표 기록` : ""}${round.abstentions ? ` · 보류 ${round.abstentions}` : ""}`;
  return { label: "검증자 합의", value, lines: [line], tone: outcomeTone(round.outcome) };
}

const roundFindings = (round?: V3Round) => (round?.votes ?? []).filter((vote) => vote.cast && vote.evidence).flatMap((vote) => vote.evidence!.findings);
export function severityCard(round?: V3Round, votes?: V3Votes | null): Card {
  const withEvidence = (round?.votes ?? []).filter((vote) => vote.cast && vote.evidence);
  if (!withEvidence.length) return { label: "최고 심각도 · 검증자 증거", value: "—", lines: ["증거 요약 없음"], tone: "neutral", bar: 0 };
  const level = Math.max(0, ...roundFindings(round).map((finding) => SEVERITY_LEVEL[finding.severity] ?? 0));
  const value = level ? Object.keys(SEVERITY_LEVEL).find((key) => SEVERITY_LEVEL[key] === level)! : "없음";
  const lanes = withEvidence.map((vote) => laneOf(votes, vote.validator)).filter(Boolean).sort().join("·");
  return { label: "최고 심각도 · 검증자 증거", value, lines: [`검증자 ${lanes || `${withEvidence.length}명`}의 증거 요약 기준 · 운영사 검사 아님`], tone: "neutral", bar: level * 25 };
}

export function groundsCard(round?: V3Round): Card {
  const votes = (round?.votes ?? []).filter((vote) => vote.cast && vote.evidence);
  const findings = roundFindings(round);
  const rules = uniqueCodes(findings.filter(isRule)).length, signals = uniqueCodes(findings.filter((finding) => !isRule(finding))).length;
  const fromWitness = votes.some((vote) => witnessed(vote) && vote.evidence!.findings.some((finding) => finding.stage === "AI"));
  const lines = !rules && !signals ? ["차단 근거 없음"] : [`의심 신호 ${signals}건 · 승인·폐기 근거 아님`,
    ...(signals ? [fromWitness ? "AI 증인 의심 포함 · PASS를 보류로만 바꿈" : "로컬 의미 규칙 · AI 모델 아님"] : [])];
  return { label: "판정 근거 · 결정론적 규칙", value: `${rules}건`, lines, tone: "neutral" };
}

export type Phase = "none" | "login" | "loading" | "operator" | "validators" | "decided" | "done" | "terminal" | "stalled" | "missing" | "error";
export function progressPhase({ scanId, signedOut = false, notFound = false, failed = false, scan, votes, round, admission, admissionPending = false, now = Date.now() }: {
  scanId?: string | null; signedOut?: boolean; notFound?: boolean; failed?: boolean; scan?: Scan | null; votes?: V3Votes | null; round?: V3Round; admission?: Admission | null; admissionPending?: boolean; now?: number;
}): Phase {
  if (!scanId) return "none";
  if (signedOut) return "login";
  if (notFound) return "missing";
  if (!scan) return failed ? "error" : "loading";
  if (scan.status === "QUEUED" || scan.status === "RUNNING") return "operator";
  if (scan.status === "DEAD_LETTER") return "error";
  if (!round) {
    if (votes?.status === "REVOKED") return "terminal";
    if (now - Date.parse(scan.updatedAt) > 180_000) return "stalled";
    return "validators";
  }
  if (round.outcome === "OPEN" || !DECIDED.has(round.outcome)) return "validators";
  // Wait (at most 45 s after the decision) for the remaining votes and, for every cast vote, a transaction and whether it came after
  // the decision (from the indexer, or from the receipt of the operator's own relay of that exact vote).
  const settledVotes = round.votes.filter((vote) => vote.cast).length >= 3
    && round.votes.every((vote) => !vote.cast || (Boolean(vote.txHash) && vote.afterDecision !== null && vote.afterDecision !== undefined));
  const sinceDecision = round.decidedAt ? now - round.decidedAt * 1000 : 0;
  if ((!settledVotes && sinceDecision < 45_000) || !admission || admissionPending) return "decided";
  return "done";
}

export type FindingRow = { code: string; severity: string; stages: string[]; deterministic: boolean; lanes: Lane[] };
/** Where a finding came from, for this vote: a stage-AI finding is the AI witness only when that validator's witness answered. */
export function stageLabel(stage: string, vote: V3Vote) {
  if (stage === "STATIC") return "정적 규칙";
  if (stage === "SANDBOX") return "시험 환경";
  if (stage === "AI") return witnessed(vote) ? "AI 증인 · 참고" : vote.evidence?.ai === undefined ? "의미 분석 · 출처 기록 없음" : "로컬 의미 규칙 (AI 모델 아님)";
  return stage;
}
/** Every code the validators' own evidence reported in this round, merged across lanes (P1 findings panel). A deterministic rule and a
 *  suspicion with the same code stay separate rows: only the first can be a FAIL ground. */
export function findingsOf(round: V3Round | undefined, votes?: V3Votes | null): FindingRow[] {
  const rows = new Map<string, FindingRow>();
  for (const vote of round?.votes ?? []) {
    if (!vote.cast || !vote.evidence) continue;
    const lane = laneOf(votes, vote.validator);
    for (const finding of vote.evidence.findings) {
      const deterministic = isRule(finding), key = `${finding.code}:${deterministic}`;
      const row = rows.get(key) ?? { code: finding.code, severity: finding.severity, stages: [], deterministic, lanes: [] };
      if ((SEVERITY_LEVEL[finding.severity] ?? 0) > (SEVERITY_LEVEL[row.severity] ?? 0)) row.severity = finding.severity;
      const stage = stageLabel(finding.stage, vote);
      if (!row.stages.includes(stage)) row.stages.push(stage);
      if (lane && !row.lanes.includes(lane)) row.lanes.push(lane);
      rows.set(key, row);
    }
  }
  return [...rows.values()].map((row) => ({ ...row, lanes: [...row.lanes].sort() }))
    .sort((a, b) => Number(b.deterministic) - Number(a.deterministic) || (SEVERITY_LEVEL[b.severity] ?? 0) - (SEVERITY_LEVEL[a.severity] ?? 0) || a.code.localeCompare(b.code));
}
export const findingNote = (row: FindingRow) => row.deterministic ? "결정론적 규칙 · FAIL 근거가 될 수 있음"
  : `의심 신호 (${row.severity}) · 승인·폐기 근거 아님${blocking(row.severity) ? " · PASS를 보류로만 바꿈" : ""}`;

export const FINDING_TEXT: Record<string, string> = {
  CANARY_EXFILTRATION: "미끼 비밀값을 통제된 로컬 수집 서버로 전송", SENSITIVE_FILE_READ: "민감 파일(주입한 미끼 포함) 읽기", UNDECLARED_EGRESS: "선언하지 않은 외부 통신",
  UNSAFE_MODULE_LOAD: "허용되지 않은 모듈 로딩 (자체 포함 프로필 밖)", TOOL_SURFACE_CHANGED: "도구 목록(tool surface)이 바뀜", SEMANTIC_BEHAVIOR_MISMATCH: "선언한 기능과 다른 동작 의심",
  HOST_ESCAPE_ATTEMPT: "시험 환경 탈출 시도", DIGEST_MISMATCH: "등록된 바이트와 다른 파일", AI_UNAVAILABLE: "AI 증인 응답 없음", SCAN_INCOMPLETE: "검사 미완료",
};

/** Release history line for the progress screen (P1). Relay receipts are labelled as not yet on chain; internal bookkeeping
 *  (outbox retries, scan state changes) returns null and is only counted. */
export function eventText(item: HistoryItem, votes?: V3Votes | null): string | null {
  const lane = laneOf(votes, item.payload?.validator) ?? "?";
  switch (item.eventName) {
    case "scan.queued": return "운영사 검사 요청 접수";
    case "validator.round.announced": return `검증자 ${lane} 라운드 수신 · 자기 사본 검사 시작`;
    case "validator.quarantine.received": return `검증자 ${lane} 긴급 격리 증거 중계 접수 · ${item.payload?.reason ?? "사유 미상"}`;
    case "validator.vote.received": return `검증자 ${lane} 서명 투표 중계 접수 · ${item.payload?.verdict ?? "?"} (체인 기록 전)`;
    case "chain.ReleaseRegistered": return "체인 기록 · 릴리스 등록";
    case "chain.RoundOpened": return "체인 기록 · 라운드 열림";
    case "chain.VoteRecorded": return `체인 기록 · 검증자 ${lane} 표${item.payload?.afterDecision === true ? " (결론 뒤)" : ""}`;
    case "chain.RoundDecided": return "체인 기록 · 라운드 결론";
    case "chain.ReleaseQuarantined": return `체인 기록 · 긴급 격리 (검증자 ${lane})`;
    case "chain.ReleaseRevoked": return "체인 기록 · 폐기 확정";
    case "chain.ReviewRequired": return "체인 기록 · 사람 검토 필요";
    case "admission.decided": return `실행 판정 조회 · ${item.payload?.decision ?? "?"} (${item.payload?.reasonCode ?? "?"})`;
    default: return null;
  }
}
/** This run's history only: events that name another scan or another round are left out, and so is everything before `since`. */
export function runHistory(history: HistoryItem[], { since, scanId, roundId }: { since?: string | null; scanId?: string | null; roundId?: string | null }) {
  return history.filter((item) => (!since || item.createdAt >= since)
    && !(scanId && typeof item.payload?.scanId === "string" && item.payload.scanId !== scanId)
    && !(roundId && typeof item.payload?.roundId === "string" && !sameHex(item.payload.roundId, roundId)));
}

/** Fixture releases the site can scan: the two reviewed mail-mcp fixtures only. */
export const FIXTURE_VERSIONS = ["1.0.0", "1.0.1"] as const;
export type FixtureVersion = (typeof FIXTURE_VERSIONS)[number];
export const isFixtureVersion = (value: unknown): value is FixtureVersion => value === "1.0.0" || value === "1.0.1";
export const fixtureRelease = (releases: Release[] | null | undefined, version: FixtureVersion) => releases?.find((item) => item.legacyReleaseId === `mail-mcp@${version}`);
export const roundOutcomeShort = (round?: V3Round) => !round ? "라운드 없음" : round.outcome === "APPROVED" ? "승인" : round.outcome === "REJECTED" ? "폐기" : round.outcome === "SPLIT" ? "표 갈림" : "투표 중";
