"use client";

import { useState } from "react";

const actions = [
  ["SCAN_SAFE", "01", "정상 버전 스캔", "Scanner가 고정된 1.0.0 fixture를 검사합니다."],
  ["VOTE_SAFE_A", "02", "Validator A · PASS", "첫 번째 EIP-712 데모 서명을 생성합니다."],
  ["VOTE_SAFE_B", "03", "Validator B · PASS", "2-of-3 정족수로 VERIFIED가 됩니다."],
  ["RUN_SAFE", "04", "안전 아티팩트 실행", "Gateway가 계산한 identity로 제한 실행합니다."],
  ["SELECT_MALICIOUS", "05", "1.0.1 업데이트 선택", "동일한 이름의 악성 후보 버전으로 전환합니다."],
  ["SCAN_MALICIOUS", "06", "악성 버전 스캔", "정적·AI·샌드박스에서 dummy canary를 추적합니다."],
  ["VOTE_FAIL_A", "07", "Validator A · FAIL", "첫 번째 실패 판정을 서명합니다."],
  ["VOTE_FAIL_B", "08", "Validator B · FAIL", "2-of-3 정족수로 REVOKED가 됩니다."],
  ["RUN_MALICIOUS", "09", "악성 버전 실행 시도", "Gateway가 entrypoint 시작 전에 차단합니다."],
] as const;

type DemoState = {
  sessionId: string; expiresAt: string; step: number; nextAction: string | null; complete: boolean;
  selectedRelease: string;
  releases: Array<{ releaseId: string; scanStatus: string; status: string }>;
  findings: Array<{ code: string; severity: string; stage: string; message: string }>;
  votes: Array<{ validator: string; address: string; releaseId: string; decision: string; signatureHash: string }>;
  executions: Array<{ releaseId: string; decision: string; spawnAttempted: boolean; reasonCode?: string; result?: unknown }>;
  events: Array<{ at: string; type: string; detail: string }>;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/judge/${path}`, { ...init, headers: init?.body ? { "content-type": "application/json" } : undefined });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload?.error?.message ?? payload?.error ?? `HTTP ${response.status}`);
  }
  return response.status === 204 ? undefined as T : response.json();
}

const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const short = (value: string) => `${value.slice(0, 8)}…${value.slice(-4)}`;

export function JudgeDemo() {
  const [demo, setDemo] = useState<DemoState | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function createSession() {
    const created = await request<DemoState>("sessions", { method: "POST" });
    setDemo(created); return created;
  }

  async function runAction(session: DemoState, action: string) {
    setRunning(action); setError(null);
    try {
      const updated = await request<DemoState>(`sessions/${session.sessionId}/actions`, { method: "POST", body: JSON.stringify({ action }) });
      setDemo(updated); return updated;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "데모 단계가 실패했습니다.");
      throw cause;
    } finally { setRunning(null); }
  }

  async function start() {
    setRunning("CREATE"); setError(null);
    try { await createSession(); } catch (cause) { setError(cause instanceof Error ? cause.message : "세션 생성에 실패했습니다."); }
    finally { setRunning(null); }
  }

  async function autoRun() {
    setRunning("AUTO"); setError(null);
    try {
      let current = await createSession();
      for (const [action] of actions) {
        setRunning(action); await wait(350);
        current = await request<DemoState>(`sessions/${current.sessionId}/actions`, { method: "POST", body: JSON.stringify({ action }) });
        setDemo(current);
      }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "자동 데모가 실패했습니다."); }
    finally { setRunning(null); }
  }

  async function reset() {
    if (demo) await request(`sessions/${demo.sessionId}`, { method: "DELETE" }).catch(() => undefined);
    await start();
  }

  const currentIndex = demo?.step ?? -1;
  const blocked = demo?.executions.find((item) => item.decision === "BLOCK");

  return (
    <main className="judge-shell">
      <nav className="judge-nav"><a href="/">← Control Room</a><span>MCPShield · Judge Lab</span><b>SYNTHETIC DEMO</b></nav>
      <header className="judge-hero">
        <div><span className="judge-kicker">NO LOGIN · NO WALLET · 15 MIN SESSION</span><h1>직접 깨뜨려 보세요.<br /><em>실행 전에 막습니다.</em></h1><p>고정된 정상·악성 fixture만 사용하는 격리형 체험입니다. 실제 Scanner, EIP-712 데모 서명, Gateway 실행 경로를 단계별로 확인하세요.</p></div>
        <div className="judge-controls">
          <button className="judge-primary" onClick={autoRun} disabled={Boolean(running)}>▶ 30초 자동 데모</button>
          <button onClick={demo ? reset : start} disabled={Boolean(running)}>{demo ? "새 세션으로 초기화" : "단계별 체험 시작"}</button>
        </div>
      </header>

      <section className="judge-truth" aria-label="Demo assurance">
        <strong>LIVE DEMO</strong><span>고정 fixture 실제 실행</span><strong>LOCAL_DEMO LEDGER</strong><span>테스트넷 트랜잭션 아님</span>
        {demo && <code title={demo.sessionId}>SESSION {short(demo.sessionId)}</code>}
      </section>

      {error && <div className="judge-error" role="alert">{error}</div>}
      {!demo ? (
        <section className="judge-empty"><div className="shield">M</div><h2>심사위원 전용 안전한 실습 환경</h2><p>임의 업로드와 외부 전송 없이 두 개의 검토된 fixture만 실행합니다.</p><button className="judge-primary" onClick={start} disabled={Boolean(running)}>{running ? "세션 준비 중…" : "체험 시작"}</button></section>
      ) : (
        <>
          <section className="judge-status" aria-live="polite">
            {demo.releases.map((release) => <article key={release.releaseId} className={demo.selectedRelease === release.releaseId ? "selected" : ""}><span>{release.releaseId.endsWith("0") ? "BASELINE" : "CANDIDATE"}</span><h2>{release.releaseId}</h2><dl><div><dt>SCAN</dt><dd>{release.scanStatus}</dd></div><div><dt>STATUS</dt><dd className={release.status === "REVOKED" ? "danger" : release.status === "VERIFIED" ? "good" : ""}>{release.status}</dd></div></dl></article>)}
            <article className="judge-verdict"><span>GATEWAY VERDICT</span><strong>{blocked ? "BLOCKED" : demo.executions.some((item) => item.decision === "ALLOW") ? "ALLOWED" : "WAITING"}</strong><p>{blocked ? "BEFORE PROCESS SPAWN" : "Exact release identity required"}</p></article>
          </section>

          <section className="judge-grid">
            <div className="judge-card judge-steps"><div className="judge-title"><span>01</span><h2>Guided attack path</h2><small>{demo.step} / {actions.length}</small></div>
              <ol>{actions.map(([action, number, label, detail], index) => { const state = index < currentIndex ? "done" : index === currentIndex ? "current" : "pending"; return <li key={action} className={state}><span>{state === "done" ? "✓" : number}</span><div><b>{label}</b><p>{detail}</p></div>{state === "current" && <button onClick={() => runAction(demo, action)} disabled={Boolean(running)}>{running === action ? "실행 중…" : "실행"}</button>}</li>; })}</ol>
            </div>

            <div className="judge-side">
              <section className="judge-card"><div className="judge-title"><span>02</span><h2>Evidence</h2><small>{demo.findings.length} findings</small></div><div className="judge-findings">{demo.findings.slice(-8).map((finding, index) => <article key={`${finding.code}-${index}`}><span className={finding.severity.toLowerCase()}>{finding.severity}</span><div><b>{finding.code}</b><p>{finding.stage} · {finding.message}</p></div></article>)}{!demo.findings.length && <p className="judge-placeholder">스캔을 실행하면 탐지 근거가 여기에 표시됩니다.</p>}</div></section>
              <section className="judge-card"><div className="judge-title"><span>03</span><h2>Validator quorum</h2><small>{demo.votes.length} signatures</small></div><div className="judge-votes">{demo.votes.map((vote, index) => <article key={`${vote.releaseId}-${vote.validator}`}><span>{index + 1}</span><div><b>{vote.validator}</b><p>{short(vote.address)} · {vote.releaseId}</p></div><strong className={vote.decision === "FAIL" ? "danger" : "good"}>{vote.decision}</strong></article>)}{!demo.votes.length && <p className="judge-placeholder">검증자 키는 서버에만 있으며 응답에는 서명 해시만 남습니다.</p>}</div></section>
            </div>
          </section>

          <section className="judge-card judge-events"><div className="judge-title"><span>04</span><h2>Execution timeline</h2><small>expires {new Date(demo.expiresAt).toLocaleTimeString("ko-KR")}</small></div><ol>{demo.events.map((item, index) => <li key={`${item.at}-${index}`}><time>{new Date(item.at).toLocaleTimeString("ko-KR", { hour12: false })}</time><div><b>{item.type}</b><p>{item.detail}</p></div></li>)}</ol>{demo.complete && <div className="judge-success"><strong>DEMO COMPLETE</strong><span>정상 실행 성공 · dummy canary 탐지 · 2-of-3 REVOKED · 악성 entrypoint 실행 전 차단</span></div>}</section>
        </>
      )}
      <footer className="judge-footer"><span>고정된 합성 데이터만 사용합니다.</span><span>임의 코드 업로드 없음 · 외부 공격 서버 없음 · 실제 개인정보 없음</span></footer>
    </main>
  );
}
