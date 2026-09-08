"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { EvidenceView } from "./evidence-view";
import { ReceiptConsole } from "./receipt-console";
import { ReleaseWorkflow, policyMatchesRelease, type Release, type Scan, type ChainAction } from "./release-workflow";
import { PreparationConsole, type Preparation } from "./preparation-console";
import { AppealRecords, type Appeal } from "./appeal-records";
import { controlApi as api } from "../lib/control-client";

type Session = { tenantId: string; role: string; capabilities: { read: boolean; scan: boolean; evidence: boolean; manage: boolean } };
type Policy = { policyHash: string; alias: string; version: string; document: unknown; createdAt: string; deprecatedAt: string | null };
type History = { eventId: string; eventName: string; createdAt: string; traceId: string; payload: unknown };
type Operations = { driver: string; counts: Record<string, number>; total: number };
const short = (value?: string | null) => value ? value.length > 28 ? `${value.slice(0, 16)}…${value.slice(-8)}` : value : "—";
const date = (value?: string | null) => value ? new Date(value).toLocaleString("ko-KR") : "기록 없음";
const field = (data: FormData, name: string) => String(data.get(name) ?? "").trim();

export function OperationsConsole() {
  const [session, setSession] = useState<Session | null>(null);
  const [releases, setReleases] = useState<Release[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [operations, setOperations] = useState<Operations | null>(null);
  const [chainActions, setChainActions] = useState<ChainAction[]>([]);
  const [preparations, setPreparations] = useState<Preparation[]>([]);
  const [scanTarget, setScanTarget] = useState("");
  const [streamState, setStreamState] = useState("자동 갱신 연결 대기");
  const refreshSequence = useRef(0), selectedRef = useRef("");
  const [selected, setSelected] = useState<string>("");
  const [history, setHistory] = useState<History[]>([]);
  const [appeals, setAppeals] = useState<Appeal[]>([]);
  const [detail, setDetail] = useState<unknown>(null);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("운영 계정으로 연결하면 현재 조직의 실제 데이터를 불러옵니다.");
  const [error, setError] = useState("");
  const release = releases.find((item) => item.releaseId === selected);

  async function refresh() {
    const sequence = ++refreshSequence.current, id = selectedRef.current;
    try {
      const [nextReleases, nextScans, nextPolicies, nextOperations, nextActions, nextPreparations, events, requests] = await Promise.all([
        api<{ items: Release[] }>("releases"), api<{ items: Scan[] }>("scans"), api<{ items: Policy[] }>("policies"), api<Operations>("operations"), api<{ items: ChainAction[] }>("chain/actions"), api<{ items: Preparation[] }>("preparations"),
        id ? api<{ items: History[] }>(`releases/${encodeURIComponent(id)}/history`) : Promise.resolve({ items: [] }), id ? api<{ items: Appeal[] }>(`releases/${encodeURIComponent(id)}/appeals`) : Promise.resolve({ items: [] }),
      ]);
      if (sequence !== refreshSequence.current) return;
      setReleases(nextReleases.items); setScans(nextScans.items); setPolicies(nextPolicies.items); setOperations(nextOperations);
      setChainActions(nextActions.items); setPreparations(nextPreparations.items); setHistory(events.items); setAppeals(requests.items);
      setNotice(`운영 API 마지막 조회 · ${new Date().toLocaleTimeString("ko-KR")}`);
    } catch (error) {
      if (sequence !== refreshSequence.current) return;
      setReleases([]); setScans([]); setChainActions([]); setPreparations([]); setOperations(null); setHistory([]); setAppeals([]);
      throw error;
    }
  }
  async function action(work: () => Promise<void>) {
    setBusy(true); setError("");
    try { await work(); } catch (error) { setError(error instanceof Error ? error.message : "요청 실패"); }
    finally { setBusy(false); }
  }
  async function selectRelease(releaseId: string) {
    const sequence = ++refreshSequence.current; selectedRef.current = releaseId;
    setSelected(releaseId); setHistory([]); setAppeals([]); setDetail(null);
    await action(async () => {
      const [events, requests] = await Promise.all([api<{ items: History[] }>(`releases/${encodeURIComponent(releaseId)}/history`), api<{ items: Appeal[] }>(`releases/${encodeURIComponent(releaseId)}/appeals`)]);
      if (sequence === refreshSequence.current) { setHistory(events.items); setAppeals(requests.items); }
    });
  }
  useEffect(() => { void api<Session>("session").then(async (current) => { setSession(current); await action(refresh); }).catch(() => {}); }, []);
  const reload = useRef(refresh); reload.current = refresh;
  useEffect(() => {
    if (!session) return;
    let disposed = false, active = false, again = false, timer: ReturnType<typeof setTimeout> | undefined;
    const stream = new EventSource("/api/control/events/stream");
    const schedule = () => {
      again = true; if (active || timer) return;
      timer = setTimeout(async () => {
        timer = undefined; if (disposed) return; active = true; again = false;
        try { await reload.current(); } catch { if (!disposed) setError("자동 갱신 조회 실패 · 이전 상태 표시는 숨겼습니다. 다시 연결하거나 수동 새로고침하세요."); }
        finally { active = false; if (again && !disposed) schedule(); }
      }, 300);
    };
    stream.onopen = () => setStreamState("변경 알림 연결됨 · 알림 수신 후 API 재조회");
    stream.addEventListener("resync", schedule);
    stream.onerror = () => setStreamState("자동 갱신 재연결 대기 · 표시된 값은 마지막 조회 기록");
    return () => { disposed = true; clearTimeout(timer); stream.close(); };
  }, [session?.tenantId, session?.role]);
  useEffect(() => { if (detail !== null) document.getElementById("ops-evidence")?.scrollIntoView({ block: "start" }); }, [detail]);
  useEffect(() => { if (selected) document.getElementById("ops-workflow")?.scrollIntoView({ block: "start" }); }, [selected]);
  function submit(event: FormEvent<HTMLFormElement>, work: (data: FormData) => Promise<void>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    void action(async () => { await work(data); form.reset(); });
  }

  return <main className="ops" lang="ko">
    <header className="ops-header"><a className="ops-brand" href="/mcp">MCPShield <span>운영 콘솔</span></a><nav aria-label="제품 메뉴"><a href="/">데모 대시보드</a><a href="/try">체험하기</a>{session && <button disabled={busy} onClick={() => void action(async () => { await api("session", undefined, "DELETE"); refreshSequence.current++; selectedRef.current = ""; setSession(null); setReleases([]); setScans([]); setPolicies([]); setDetail(null); setSelected(""); setOperations(null); setChainActions([]); setPreparations([]); setScanTarget(""); setHistory([]); setAppeals([]); })}>로그아웃</button>}</nav></header>
    <section className="ops-title"><p className="ops-eyebrow">RELEASE SECURITY OPERATIONS</p><h1>검증부터 이의제기까지,<br />릴리스의 현재 상태를 한곳에서.</h1><p>등록된 릴리스, 검사 작업, 정책과 감사 기록을 조회하고 필요한 조치를 실행하세요.</p></section>
    <div className={error ? "ops-message error" : "ops-message"} role={error ? "alert" : "status"}>{error || notice}</div>
    {!session ? <section className="ops-panel ops-login"><h2>조직에 연결</h2><p>관리자가 발급한 운영 액세스 토큰을 입력하세요. 계정에 지정된 조직과 역할만 접근할 수 있습니다.</p><form method="post" onSubmit={(event) => submit(event, async (data) => { const current = await api<Session>("session", { token: field(data, "token") }); setSession(current); await refresh(); })}><label>액세스 토큰<input name="token" type="password" required minLength={16} maxLength={2048} autoComplete="off" /></label><button disabled={busy}>운영 콘솔 연결</button></form><small>토큰은 JavaScript에서 읽을 수 없는 HttpOnly 쿠키로 보관하며, 주소나 localStorage에 기록하지 않습니다.</small></section> : <>
      <div className="ops-session"><span><b>{session.tenantId}</b> · {session.role}</span><span>실제 API · 체인 증빙은 릴리스별 표시</span><button disabled={busy} onClick={() => void action(refresh)}>새로고침</button></div>
      <p className="ops-data-note" role="status">{streamState}. 변경 알림은 상태·승인 증거가 아니며 공개 체험 데이터와 섞이지 않습니다.</p>
      <section className="ops-stats" aria-label="현재 조직 운영 현황"><article><span>등록 릴리스</span><strong>{releases.length}</strong></article><article><span>검사 대기 / 실행</span><strong>{operations ? (operations.counts.QUEUED ?? 0) + (operations.counts.RUNNING ?? 0) : "—"}</strong></article><article><span>재처리 필요</span><strong>{operations?.counts.DEAD_LETTER ?? "—"}</strong></article><article><span>격리 / 폐기</span><strong>{releases.filter((item) => ["QUARANTINED", "REVOKED"].includes(item.status)).length}</strong></article></section>
      {operations && <p className="ops-data-note">{operations.driver} 연결 · 조직 전체 검사 {operations.total}개 · 목록은 최근 최대 250개 · 릴리스·폐기 개수는 불러온 목록 기준</p>}
      {release && <section id="ops-workflow" className="ops-panel"><h2>{release.legacyReleaseId || release.toolId} · 검증 흐름</h2><ReleaseWorkflow key={release.releaseId} release={release} scans={scans} policies={policies} actions={chainActions} manage={session.capabilities.manage} onRefresh={refresh} /></section>}
      <PreparationConsole key={`${session.tenantId}:${session.role}`} jobs={preparations} releases={releases} policies={policies} operator={session.capabilities.scan && session.capabilities.evidence} onRefresh={refresh} onSelect={id => void selectRelease(id)} />
      {session.capabilities.scan && <section className="ops-panel"><h2>새 릴리스 등록</h2><p>정확한 버전을 입력하세요. 다운로드된 파일의 digest로 릴리스를 고정합니다.</p><form method="post" className="ops-inline-form" onSubmit={(event) => submit(event, async (data) => { await api("releases/resolve", { sourceType: field(data, "sourceType"), locator: field(data, "locator") }); await refresh(); })}><label>가져올 위치<select name="sourceType"><option value="npm">npm 패키지</option><option value="tarball">Tarball URL</option><option value="oci">OCI 이미지 (digest 고정)</option><option value="fixture">로컬 데모 fixture</option></select></label><label>정확한 패키지 또는 주소<input name="locator" required maxLength={2048} placeholder="패키지@1.0.0 / mail-mcp-1.0.0" /></label><button disabled={busy}>릴리스 등록</button></form></section>}
      <section className="ops-panel"><div className="ops-section-heading"><h2>릴리스 인벤토리</h2><span>검증 유효기간과 증거를 함께 확인하세요.</span></div><div className="ops-filters"><label>릴리스 검색<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="이름, 버전, digest" /></label><label>상태<select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">모든 상태</option>{["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"].map((item) => <option key={item}>{item}</option>)}</select></label></div><div className="ops-table-wrap"><table><thead><tr><th>릴리스</th><th>상태</th><th>유효기간</th><th>증빙 수준</th><th>상세</th></tr></thead><tbody>{releases.filter((item) => (!status || item.status === status) && `${item.legacyReleaseId} ${item.toolId} ${item.version} ${item.artifactDigest} ${item.releaseId}`.toLowerCase().includes(query.toLowerCase())).map((item) => <tr key={item.releaseId}><td><b>{item.legacyReleaseId || `${item.toolId}@${item.version}`}</b><small>{item.runtimeProfile ? "준비된 실행 릴리스" : "원본 릴리스"} · {item.sourceType ?? "출처 미제공"}</small><small title={item.releaseId}>ID {short(item.releaseId)}</small><small title={item.artifactDigest}>{short(item.artifactDigest)}</small></td><td><span className={`ops-badge ${item.status.toLowerCase()}`}>{item.status}</span></td><td>{date(item.validUntil)}</td><td>{item.chainUnavailable ? "현재 조회 불가 · 이전 기록 참고" : item.chain ? `EVM · block ${item.chain.observedBlock}` : "체인 증빙 없음"}</td><td><button disabled={busy} onClick={() => void selectRelease(item.releaseId)}>열기</button></td></tr>)}</tbody></table>{!releases.length && <p className="ops-empty">아직 등록된 릴리스가 없습니다. 릴리스를 등록하면 여기에 표시됩니다.</p>}</div></section>
      {release && <section className="ops-panel" aria-label="선택한 릴리스"><div className="ops-section-heading"><h2>{release.legacyReleaseId || release.toolId}</h2><span className={`ops-badge ${release.status.toLowerCase()}`}>{release.status}</span></div><dl className="ops-facts">{[["Release ID", release.releaseId], ["Artifact digest", release.artifactDigest], ["Tool surface", release.toolSurfaceHash], ["Policy", release.policyHash], ["Evidence root", release.reportRoot], ["Valid until", date(release.validUntil)], ["Chain availability", release.chainUnavailable ? "현재 조회 불가 · 아래는 이전 기록" : release.chain ? "인덱서 관측 있음" : "증빙 없음"], ["Chain transaction", release.chain?.txHash], ["Observed block hash", release.chain?.blockHash]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || "기록 없음"}</dd></div>)}</dl><div className="ops-columns"><div><h3>변경 이력</h3>{history.length ? <ol className="ops-events">{history.map((item) => <li key={item.eventId}><b>{item.eventName}</b><small>{date(item.createdAt)} · trace {short(item.traceId)}</small><details><summary>이벤트 상세</summary><pre>{JSON.stringify(item.payload, null, 2)}</pre></details></li>)}</ol> : <p className="ops-empty">기록된 이벤트가 없습니다.</p>}</div><div><h3>오탐 신고·재검증 요청</h3>{session.capabilities.scan && <form method="post" onSubmit={(event) => submit(event, async (data) => { await api(`releases/${encodeURIComponent(selected)}/appeals`, { reason: String(data.get("reason") ?? "") }); await refresh(); setNotice("이의제기가 릴리스 이력에 접수되었습니다."); })}><label>재검토가 필요한 이유<textarea name="reason" required minLength={10} maxLength={2000} rows={3} placeholder="실제 비밀값 대신 재현 조건과 기대 동작을 적어주세요." /></label><button disabled={busy}>이의제기 접수</button></form>}<AppealRecords appeals={appeals} manage={session.capabilities.manage} busy={busy} onResolve={(event, appeal) => submit(event, async (data) => { await api(`appeals/${encodeURIComponent(appeal.appealId)}/resolve`, { resolution: String(data.get("resolution") ?? "") }); await refresh(); setNotice("이의제기 종결 기록을 다시 조회했습니다. 실행 승인이나 폐기 해제가 아니며 변경 이력을 확인하세요."); })} /></div></div></section>}
      <section className="ops-panel"><div className="ops-section-heading"><h2>검사 작업과 재처리</h2><span>영구 실패는 원인을 확인한 후 재요청하세요.</span></div>{session.capabilities.scan && <form method="post" className="ops-inline-form" onSubmit={(event) => submit(event, async (data) => { await api("scans", { releaseId: field(data, "releaseId"), policyHash: field(data, "policyHash") }); await refresh(); setScanTarget(""); })}><label>검사할 릴리스<select name="releaseId" required value={scanTarget} onChange={event => setScanTarget(event.target.value)}><option value="">릴리스 선택</option>{releases.map((item) => <option value={item.releaseId} key={item.releaseId}>{item.legacyReleaseId || item.toolId} · {item.runtimeProfile ? "실행 릴리스" : "원본"}</option>)}</select></label><label>프로필에 맞는 정책<select name="policyHash" key={scanTarget} required disabled={!scanTarget}><option value="">정책 선택</option>{policies.filter((item) => !item.deprecatedAt && policyMatchesRelease(releases.find(release => release.releaseId === scanTarget), item)).map((item) => <option value={item.policyHash} key={item.policyHash}>{item.alias} · {item.version}</option>)}</select></label><button disabled={busy || !scanTarget || !policies.length}>검사 요청</button></form>}<div className="ops-table-wrap"><table><thead><tr><th>작업 / 추적 ID</th><th>상태 / 단계</th><th>시도</th><th>최근 변경</th><th>작업</th></tr></thead><tbody>{scans.map((scan) => <tr key={scan.scanId}><td title={scan.scanId}>{short(scan.scanId)}<small title={scan.traceId}>trace {short(scan.traceId)}</small></td><td><b>{scan.status}</b><small>{scan.stage}{scan.result?.scanResult?.scanStatus ? ` · 분석: ${scan.result.scanResult.scanStatus}` : ""}</small></td><td>{scan.attempts} / {scan.maxAttempts}</td><td>{date(scan.updatedAt)}</td><td className="ops-actions"><button disabled={busy} onClick={() => setDetail(scan)}>상세</button>{session.capabilities.evidence && scan.status === "COMPLETED" && <button disabled={busy} onClick={() => void action(async () => setDetail(await api(`scans/${encodeURIComponent(scan.scanId)}/evidence`)))}>증거 보기</button>}{session.capabilities.scan && scan.status === "DEAD_LETTER" && <button disabled={busy} onClick={() => void action(async () => { await api(`scans/${encodeURIComponent(scan.scanId)}/retry`, {}); await refresh(); })}>재처리</button>}</td></tr>)}</tbody></table>{!scans.length && <p className="ops-empty">실행한 검사 작업이 없습니다.</p>}</div></section>
      <section className="ops-panel"><h2>정책 레지스트리</h2><div className="ops-policies">{policies.map((policy) => <article key={policy.policyHash}><h3>{policy.alias} <small>{policy.version}</small></h3><span className="ops-badge">{policy.deprecatedAt ? "DEPRECATED" : "ACTIVE"}</span><p><code title={policy.policyHash}>{short(policy.policyHash)}</code></p><details><summary>정책 내용</summary><pre>{JSON.stringify(policy.document, null, 2)}</pre></details></article>)}</div>{!policies.length && <p className="ops-empty">등록된 정책이 없습니다. 관리자가 정책을 등록해야 검사를 시작할 수 있습니다.</p>}</section>
      {session.capabilities.manage && <section className="ops-panel"><h2>검증 정책 등록</h2><p>정적·의미·샌드박스 검사와 결정론적 폐기 근거를 모두 요구하는 정책을 등록합니다. 변경된 정책은 새 해시로 식별됩니다.</p><form method="post" className="ops-inline-form" onSubmit={(event) => submit(event, async (data) => { await api("policies", { alias: field(data, "alias"), document: { version: "1.0.0", validitySeconds: Number(field(data, "validitySeconds")), requiredTiers: ["static", "semantic", "sandbox"], failClosed: true, maxArtifactBytes: 16_777_216, maxDailyScans: Number(field(data, "maxDailyScans")), maxQueuedScans: 20, deterministicRevocationRequired: true } }); await refresh(); })}><label>정책 이름<input name="alias" required maxLength={80} placeholder="team-standard" /></label><label>검증 유효기간 (초)<input name="validitySeconds" type="number" min={60} max={2592000} defaultValue={86400} required /></label><label>일일 검사 한도<input name="maxDailyScans" type="number" min={1} max={1000} defaultValue={100} required /></label><button disabled={busy}>정책 등록</button></form></section>}
      <ReceiptConsole key={`${session.tenantId}:${session.role}`} manage={session.capabilities.manage} evidenceAccess={session.capabilities.evidence} />
      {detail !== null && <section id="ops-evidence" className="ops-panel"><div className="ops-section-heading"><h2>작업·증거 상세</h2><button onClick={() => setDetail(null)}>닫기</button></div><p>증거 조회 권한은 API에서 확인하며 접근 기록을 남깁니다.</p><EvidenceView evidence={detail} /></section>}
    </>}
    <footer className="ops-footer"><b>MCPShield</b><span>공개 체험 데이터와 조직 운영 데이터는 별도로 관리됩니다.</span><a href="/mcp#connect">MCP 연결 안내</a></footer>
  </main>;
}
