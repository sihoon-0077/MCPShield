// Presentational pieces of the V3 scan screens. Plain <a href> (no next/link, no router hooks) so tests can render them.
// Every root carries data-raw: the KR/EN text translator must never rewrite an API value.
import React from "react";
import type { Admission, Release, V3Round, V3Votes } from "../release-workflow";
import type { Board } from "./v3-api";
import { AI_WITNESS_NOTE, FINDING_TEXT, LANES, TEAM_RUN_NOTE, ago, clock, consensusCard, eventText, findingNote, findingsOf, groundsCard, roundOutcomeShort, runHistory,
  severityCard, short, toolName, verdictCard, verdictKo, type Cell, type FlowView, type HistoryItem, type LaneView, type Step, type Witness } from "./v3-model";

const mark = (tone: string) => <svg className="v3-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
  {tone === "pass" ? <path d="m5 12 4 4L19 6" /> : <><path d="M12 3 2.8 20h18.4L12 3Z" /><path d="M12 9v5M12 17h.01" /></>}</svg>;

export function LoginRequired() {
  return <div className="v3-login" data-raw role="status">
    <b>운영자 로그인이 필요합니다</b>
    <p>검사 요청과 체인 기록은 운영 API에서 읽습니다. 운영 콘솔에서 액세스 토큰으로 로그인하면 이 화면에도 그대로 적용됩니다(8시간).</p>
    <a className="ws-button primary" href="/console">운영 콘솔에서 로그인</a>
  </div>;
}

const pillClass = (verdict?: string | null) => `vote-pill ${verdict === "PASS" ? "pass" : verdict === "FAIL" ? "fail" : verdict === "ABSTAIN" ? "abstain" : "none"}`;
/** One pill per validator lane A, B, C for the given round: its own on-chain verdict, or "—" when it has not voted. */
export function VotePills({ votes, round }: { votes?: V3Votes | null; round?: V3Round }) {
  return <span className="vote-pills" data-raw>{LANES.map((lane, index) => {
    const address = votes?.validators?.[index];
    const vote = round?.votes.find((item) => address && item.validator.toLowerCase() === address.toLowerCase());
    const verdict = vote?.cast ? vote.verdict : null;
    return <span key={lane} className={pillClass(verdict)}>{lane} {verdict ? verdictKo(verdict) : "—"}</span>;
  })}</span>;
}

const Tx = ({ tx }: { tx: NonNullable<Cell["tx"]> }) => <span>{tx.label ?? "거래"} {tx.href ? <a href={tx.href} target="_blank" rel="noreferrer"><code>{short(tx.hash)}</code></a> : <code title={tx.hash}>{short(tx.hash)}</code>}</span>;
// Shortened hashes stay on one line (<code>, nowrap); long codes such as CANARY_EXFILTRATION may break after "_" only, and a
// " · " separated part never breaks inside itself unless it has to.
const HASH = /((?:0x|sha256:)[0-9a-fA-F]{3,}…[0-9a-fA-F]{4})/;
function Plain({ value }: { value: string }) {
  return <>{value.split(HASH).map((part, index) => index % 2 ? <code key={index}>{part}</code>
    : part.split(/(?<=_)/).map((piece, at) => <React.Fragment key={`${index}-${at}`}>{at ? <wbr /> : null}{piece}</React.Fragment>))}</>;
}
function Text({ value }: { value: string }) {
  const parts = value.split(" · ");
  if (parts.length === 1) return <Plain value={value} />;
  return <>{parts.map((part, index) => <React.Fragment key={index}>{index ? " · " : null}<span className="v3-seg"><Plain value={part} /></span></React.Fragment>)}</>;
}

function StepView({ step, extra }: { step: Step; extra?: Record<string, string> }) {
  return <div className={`v3-step tone-${step.tone}`} data-step={step.key} data-state={step.state} {...extra}>
    <small>{step.index} · {step.name}</small><small className="v3-caption">{step.caption}</small>
    <b><Text value={step.title} /></b>{step.lines.map((line) => <span key={line}><Text value={line} /></span>)}{step.tx && <Tx tx={step.tx} />}
  </div>;
}

function CellView({ cell, label, extra }: { cell: Cell; label: string; extra?: Record<string, string> }) {
  return <div className={`v3-cell tone-${cell.tone}`} data-state={cell.state} {...extra}>
    <small>{label}</small><b><Text value={cell.title} /></b>{cell.lines.map((line) => <span key={line}><Text value={line} /></span>)}{cell.tx && <Tx tx={cell.tx} />}
  </div>;
}

function WitnessView({ witness }: { witness: Witness }) {
  const state = witness.state === "waiting" ? { "data-state": "pending" } : witness.state === "answered" || witness.state === "silent" ? { "data-state": "done" } : {};
  return <div className={`v3-cell tone-${witness.tone}`} data-witness={witness.state} {...state}>
    <small>AI 증인 (이 표)</small><b>{witness.model ? <><code>{witness.model}</code> · <Text value={witness.label} /></> : <Text value={witness.label} />}</b>{witness.note && <span>{witness.note}</span>}
  </div>;
}

const witnessLine = (witness: Witness) => witness.model ? `${witness.model} · ${witness.label}` : witness.label;

// The flow map shows states only: a five-step stepper and one row of dots per validator. Hashes, grounds and transactions stay
// in the page, inside each row and the chain-record block, and open on click.
type DotKind = "pending" | "running" | "pass" | "fail" | "review" | "done" | "skip";
const DOT_LABELS = ["재검사", "AI 증인", "서명 투표", "긴급 격리"];
const cellKind = (cell: Cell): DotKind => cell.state === "pending" ? "pending" : cell.state === "running" ? "running" : cell.state === "failed" || cell.tone === "fail" ? "fail"
  : cell.tone === "pass" ? "pass" : cell.tone === "review" ? "review" : "done";
/** "skip" is a step that did not apply: no AI witness on this vote, or no quarantine used. A witness is never drawn in the PASS colour. */
function laneDots(lane: LaneView): { kind: DotKind; tip: string }[] {
  const witness: DotKind = lane.witness.state === "waiting" ? "pending" : lane.witness.state === "none" || lane.witness.state === "unknown" ? "skip" : lane.witness.tone === "review" ? "review" : "done";
  const quarantine: DotKind = lane.quarantine.state === "done" && lane.quarantine.tone === "neutral" ? "skip" : cellKind(lane.quarantine);
  return [{ kind: cellKind(lane.rescan), tip: lane.rescan.title }, { kind: witness, tip: witnessLine(lane.witness) },
    { kind: cellKind(lane.signed), tip: lane.signed.title }, { kind: quarantine, tip: lane.quarantine.title }];
}
function laneChip(lane: LaneView): { kind: string; label: string } {
  if (lane.voteKey !== "NONE") return { kind: lane.voteKey === "PASS" ? "pass" : lane.voteKey === "FAIL" ? "fail" : "review", label: verdictKo(lane.voteKey) };
  const active = [lane.rescan, lane.signed].some((cell) => cell.state !== "pending");
  return active ? { kind: "running", label: "검증 중" } : { kind: "pending", label: "대기" };
}
/** One dot per validator (its vote in the shown round) and one for a release's chain status. */
export const laneDotKind = (lane: LaneView): DotKind => lane.voteKey === "PASS" ? "pass" : lane.voteKey === "FAIL" ? "fail" : lane.voteKey === "ABSTAIN" ? "review"
  : [lane.rescan, lane.signed].some((cell) => cell.state !== "pending") ? "running" : "pending";
export const statusDotKind = (status: string | null): DotKind => status === "VERIFIED" ? "pass" : status === "REVOKED" || status === "QUARANTINED" ? "fail" : "pending";
const stageKind = (step: Step): DotKind => step.state === "failed" ? "fail" : step.state === "running" ? "running" : step.state === "pending" ? "pending"
  : step.tone === "fail" ? "fail" : step.tone === "review" ? "review" : "pass";

/** Stage map: operator (register, announce) → validators A/B/C each on its own → 2-of-3 on chain → Gateway admission (API lookup). */
export function V3FlowMap({ flow, compact = false }: { flow: FlowView; compact?: boolean }) {
  const [register, announce, lanes, decision, gateway] = flow.steps;
  if (compact) return <div className="v3-flow-wrap compact" data-flow data-raw>
    <div className="v3-flow compact">
      {flow.lanes.map((lane) => <div className="v3-row" key={lane.lane} data-lane={lane.lane} data-vote={lane.voteKey}>
        <span>검증자 {lane.lane} · {lane.role}{lane.witness.state !== "waiting" && <small>이번 표의 AI 증인: {witnessLine(lane.witness)}</small>}</span>
        <span className={pillClass(lane.voteKey === "NONE" ? null : lane.voteKey)}>{lane.lane} {lane.voteKey === "NONE" ? "—" : verdictKo(lane.voteKey)}</span>
      </div>)}
      <div className={`v3-row tone-${decision.tone}`} data-step="decision" data-state={decision.state} data-decision={flow.outcome ?? "NONE"}><span>04 · 2-of-3 판정</span><b><Text value={decision.title} /></b></div>
      <div className={`v3-row tone-${gateway.tone}`} data-step="gateway" data-state={gateway.state} data-gateway={flow.gateway ?? "NONE"}><span>05 · Gateway 실행 판정</span><b><Text value={gateway.title} /></b></div>
    </div>
    <p className="v3-note">A·B·C는 팀이 운영하는 역할 이름입니다 (SINGLE_INSTITUTION_DEMO). AI는 증인일 뿐 승인·폐기 권한이 없습니다.</p>
  </div>;
  return <div className="v3-flow-wrap fx" data-flow data-raw>
    <ol className="fx-stepper">{flow.steps.map((step) => { const kind = stageKind(step); return <li className={`fx-stage ${kind}`} key={step.key} data-stage={step.key}>
      <span className="fx-node">{kind === "pass" ? mark("pass") : kind === "fail" ? mark("fail") : step.index}</span>
      <b>{step.name}</b><small><Text value={step.title} /></small>
    </li>; })}</ol>
    <div className="fx-validators">
      <div className="fx-head"><b>{lanes.name}</b><span className="fx-track">{DOT_LABELS.map((label) => <i key={label}>{label}</i>)}</span><em>판정</em></div>
      {flow.lanes.map((lane) => { const chip = laneChip(lane); return <details className="fx-lane" key={lane.lane} data-lane={lane.lane} data-vote={lane.voteKey}>
        <summary>
          <span className="fx-who"><i>{lane.lane}</i>검증자 {lane.lane}</span>
          <span className="fx-track">{laneDots(lane).map((dot, index) => <i key={DOT_LABELS[index]} className={`fx-dot ${dot.kind}`} data-tip={`${DOT_LABELS[index]} · ${dot.tip}`} />)}</span>
          <span className={`fx-chip ${chip.kind}`}>{chip.label}</span>
        </summary>
        <div className="v3-lane">
          <div className="v3-cell v3-lane-head"><b>검증자 {lane.lane}</b><span>역할 · {lane.role}</span><code title={lane.address ?? ""}>{short(lane.address)}</code></div>
          <CellView cell={lane.rescan} label="자기 사본 재검사" />
          <WitnessView witness={lane.witness} />
          <CellView cell={lane.signed} label="서명 투표" />
          <CellView cell={lane.quarantine} label="긴급 격리" extra={{ "data-quarantine": lane.quarantine.title.startsWith("긴급 격리 실행") ? "yes" : "no" }} />
        </div>
      </details>; })}
      <p className="fx-legend"><i className="fx-dot pass" /> 통과 <i className="fx-dot running" /> 진행 중 <i className="fx-dot fail" /> 실패 <i className="fx-dot review" /> 보류 <i className="fx-dot skip" /> 해당 없음 <span>줄을 누르면 근거와 거래를 볼 수 있습니다</span></p>
    </div>
    <details className="fx-more">
      <summary>등록 · 라운드 · 판정의 체인 기록 보기</summary>
      <div className="fx-more-grid"><StepView step={register} /><StepView step={announce} /><StepView step={decision} extra={{ "data-decision": flow.outcome ?? "NONE" }} /><StepView step={gateway} extra={{ "data-gateway": flow.gateway ?? "NONE" }} /></div>
    </details>
    <p className="v3-note">{TEAM_RUN_NOTE}<br />{AI_WITNESS_NOTE}{flow.lanes.some((lane) => lane.signed.tx?.label) && ` ${RELAY_TX_NOTE}`}</p>
  </div>;
}
const RELAY_TX_NOTE = "중계로 표시된 해시는 인덱서가 읽기 전, 운영사가 보낸 그 표의 거래를 성공 영수증으로 확인한 것입니다.";

/** The four result cards. Only the current chain state plus an ALLOW from the API makes the verdict card green. */
export function VerdictCards({ votes, release, admission, round, loading = false, votesError = null }: { votes?: V3Votes | null; release?: Release | null; admission?: Admission | null; round?: V3Round; loading?: boolean; votesError?: string | null }) {
  const verdict = verdictCard({ votes, release, admission, loading, votesError }), consensus = consensusCard(round), severity = severityCard(round, votes), grounds = groundsCard(round);
  const tone = verdict.tone === "pass" ? "allowed" : verdict.tone === "fail" ? "" : verdict.tone;
  return <section className="metric-row v3-cards" data-raw>
    <article className={`metric-card verdict ${tone}`} data-final={verdict.value === "—" ? "NONE" : verdict.value}><small>{verdict.label}</small><div>{mark(verdict.tone)}<strong>{verdict.value}</strong></div>
      {verdict.lines.map((line) => <p key={line}>{line}</p>)}</article>
    <article className={`metric-card consensus tone-${consensus.tone}`}><small>{consensus.label}</small><strong>{consensus.value}</strong>{consensus.lines.map((line) => <p key={line}>{line}</p>)}<VotePills votes={votes} round={round} /></article>
    <article className="metric-card"><small>{severity.label}</small><strong>{severity.value}</strong>{severity.lines.map((line) => <p key={line}>{line}</p>)}<div className="metric-bar"><b style={{ width: `${severity.bar ?? 0}%` }} /></div></article>
    <article className="metric-card"><small>{grounds.label}</small><strong>{grounds.value}</strong>{grounds.lines.map((line) => <p key={line}>{line}</p>)}</article>
  </section>;
}

/** Operator API scans, newest first. A finished operator scan announces one validator round; a reused result opens none. */
export function RunsTable({ board, limit }: { board: Pick<Board, "scans" | "releases" | "votes">; limit?: number }) {
  const scans = [...board.scans].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, limit ?? board.scans.length);
  return <div className="scan-table v3-runs" data-raw>
    <div className="table-row table-labels"><span>도구 · 버전</span><span>운영사 검사</span><span>검증자 표</span><span>라운드 결론</span><span>시각</span><span /></div>
    {scans.map((scan) => {
      const release = board.releases.find((item) => item.releaseId === scan.releaseId), votes = board.votes[scan.releaseId];
      const round = votes?.rounds.find((item) => item.scanId === scan.scanId);
      const tone = round?.outcome === "APPROVED" ? "allowed" : round?.outcome === "REJECTED" ? "blocked" : "review";
      const name = toolName(release);
      return <div className="table-row" data-scan-row key={scan.scanId}>
        <span className="tool-name"><i>{name === "—" ? "?" : name.slice(0, 1).toUpperCase()}</i><b>{name}</b><code>{release?.version ?? "?"}</code></span>
        <span>{scan.status} · 권고 {scan.result?.verdict ?? "—"}</span>
        <span><VotePills votes={votes} round={round} /></span>
        <span><b className={`status ${tone}`}>{roundOutcomeShort(round)}</b></span>
        <span>{ago(scan.createdAt)}</span>
        <a className="v3-open" href={`/scan-results?scan=${scan.scanId}`} aria-label={`검사 ${scan.scanId.slice(0, 8)} 결과 열기`}>›</a>
      </div>;
    })}
  </div>;
}

/** Codes from the validators' own evidence summaries (not the operator scan), merged across lanes. A suspicion gets a neutral
 *  "참고" pill: it can hold a PASS, never approve or revoke. A stage-AI finding is called AI only for a vote whose witness answered. */
export function FindingsPanel({ round, votes }: { round?: V3Round; votes?: V3Votes | null }) {
  const rows = findingsOf(round, votes), summarized = (round?.votes ?? []).some((vote) => vote.cast && vote.evidence);
  return <div className="finding-list v3-findings" data-raw>
    {rows.map((row) => <div className="finding" key={`${row.code}:${row.deterministic}`} data-finding={row.code} data-deterministic={String(row.deterministic)}>
      {row.deterministic ? <span className={`severity ${row.severity.toLowerCase()}`}>{row.severity}</span> : <span className="severity note">참고</span>}
      <div><b>{row.code}</b><p>{FINDING_TEXT[row.code] ?? "설명 없음"}</p><p>{findingNote(row)}</p></div>
      <small>{row.stages.join(" · ")}<br />보고 검증자 {row.lanes.join("·") || "?"}</small>
    </div>)}
    {!rows.length && <div className="finding"><span className="severity low">없음</span><div><b>{summarized ? "탐지 항목 없음" : "증거 요약 없음"}</b><p>{summarized ? "검증자 증거 요약에 탐지 항목이 없습니다." : "이 라운드의 표에 증거 요약이 아직 없습니다."}</p></div></div>}
  </div>;
}

/** This run's release history, oldest first. A relay receipt is labelled as not yet on chain; internal bookkeeping is only counted. */
export function EventsList({ history, votes, since, scanId, roundId }: { history: HistoryItem[]; votes?: V3Votes | null; since?: string | null; scanId?: string | null; roundId?: string | null }) {
  // The API lists newest first; reverse before the stable sort so events within the same millisecond keep their real order.
  const mine = runHistory(history, { since, scanId, roundId }).slice().reverse().sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const items = mine.map((item) => ({ item, text: eventText(item, votes) })).filter((entry) => entry.text !== null);
  const internal = mine.length - items.length;
  return <div className="v3-events" data-raw>
    <ol>{items.map(({ item, text }, index) => <li key={`${item.createdAt}-${item.eventName}-${index}`} className={item.eventName.startsWith("chain.") ? "chain" : item.eventName.startsWith("validator.") ? "relay" : ""}>
      <time>{clock(item.createdAt)}</time><span>{text}</span>
    </li>)}</ol>
    {!items.length && <p className="v3-note">아직 기록이 없습니다.</p>}
    {internal > 0 && <p className="v3-note">내부 처리 기록 {internal}건(체인 전송 재시도·검사 상태 변경)은 목록에서 뺐습니다.</p>}
  </div>;
}
export const shownEvents = (history: HistoryItem[], votes: V3Votes | null | undefined, filter: { since?: string | null; scanId?: string | null; roundId?: string | null }) =>
  runHistory(history, filter).filter((item) => eventText(item, votes) !== null).length;
