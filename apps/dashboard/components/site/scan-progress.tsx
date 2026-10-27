'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { LanguageSwitcher, useLanguage } from './i18n'
import { localizeEvent } from './backend-text'
import { Icon, Sidebar } from './workspace'
import { ACTIONS, PLAN, STAGES, ScanApiError, clock, errorText, findRecord, getSession, runAction, saveRecord, short, stageStatuses, statusOf, wait, type DemoSession, type ScanRecord, type StageStatus, type Target } from './scan-session'

type ScanState = 'initializing' | 'scanning' | 'waiting' | 'completed' | 'failed'

// Pause between backend steps so each stage stays readable; every step is a real API call.
const STEP_DELAY_MS = 700
// The scanner returns Artifact Fetch through Sandbox Check in one response, so the screen
// reveals those real results one stage at a time and holds the next backend step until it catches up.
const REVEAL_MS = 650

const stageCopy: [string, string][] = [
  ['아티팩트를 수집하고 있습니다.', '패키지를 가져와 artifact digest와 tool surface를 계산합니다.'],
  ['정적 분석을 진행하고 있습니다.', '민감 파일 접근 · 선언되지 않은 네트워크 · 도구 표면 변경을 코드에서 찾습니다.'],
  ['AI 위험 분석', '도구의 선언된 기능과 실제 동작 패턴을 비교하고 있습니다.'],
  ['샌드박스 검사를 진행하고 있습니다.', '격리 환경에서 실행해 canary 유출과 외부 연결을 관찰합니다.'],
  ['검증자 판정 대기', '독립 검증자의 EIP-712 서명을 수집하고 있습니다.'],
  ['최종 실행 결정', 'Gateway가 검증 결과로 실행 허용 또는 차단을 결정합니다.'],
]
const baselineCopy: [string, string] = ['기준 버전을 먼저 검증하고 있습니다.', '기준 버전 mail-mcp@1.0.0을 스캔 · 서명 · 실행해 비교 기준을 만듭니다.']
const initializingCopy: [string, string] = ['검사 환경을 준비하고 있습니다.', '도구 정보와 분석 정책을 확인하는 중입니다.']
const completedCopy: [string, string] = ['검사가 완료되었습니다.', '모든 분석 단계와 검증자 판정이 완료되었습니다.']
const failedTitle = '검사를 완료하지 못했습니다.'

// Leading stages the backend has finished (stage statuses are always complete…, running…, pending…).
const doneCount = (step: number, target: Target) => stageStatuses(step, target, false).filter((status) => status === 'complete').length

export function ScanProgress({ sessionId, target }: { sessionId: string | null; target: Target }) {
  const [session, setSession] = useState<DemoSession | null>(null)
  const [error, setError] = useState<{ message: string; expired: boolean } | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [shown, setShown] = useState(0)
  const language = useLanguage()
  const shownRef = useRef(0)
  const total = PLAN[target].total
  const step = session?.step ?? 0
  const realDone = session ? doneCount(step, target) : 0

  useEffect(() => { shownRef.current = shown }, [shown])
  useEffect(() => {
    if (shown >= realDone) return
    const timer = setTimeout(() => setShown((value) => value + 1), REVEAL_MS)
    return () => clearTimeout(timer)
  }, [shown, realDone])

  useEffect(() => {
    if (!sessionId) return
    let alive = true
    ;(async () => {
      let record: ScanRecord | undefined = findRecord(sessionId)
      try {
        let current = await getSession(sessionId)
        const now = new Date().toISOString()
        record ??= { sessionId, target, status: 'RUNNING', startedAt: current.createdAt, updatedAt: now, baselineFindingCount: null, session: current }
        if (alive) setSession(current)
        while (alive && current.step < total) {
          while (alive && shownRef.current < doneCount(current.step, target)) await wait(100)
          const [action] = ACTIONS[current.step]
          await wait(STEP_DELAY_MS)
          if (!alive) return
          current = await runAction(sessionId, action)
          record = { ...record, session: current, updatedAt: new Date().toISOString(), status: current.step < total ? 'RUNNING' : statusOf(current, target), error: undefined }
          if (action === 'SCAN_SAFE') record.baselineFindingCount = current.findings.length
          saveRecord(record)
          if (alive) setSession(current)
        }
      } catch (cause) {
        if (record) saveRecord({ ...record, status: 'FAILED', updatedAt: new Date().toISOString(), error: errorText(cause) })
        if (alive) setError({ message: errorText(cause), expired: cause instanceof ScanApiError && cause.status === 404 })
      }
    })()
    return () => { alive = false }
  }, [sessionId, target, total, attempt])

  const real = session ? stageStatuses(step, target, Boolean(error)) : STAGES.map((_, index): StageStatus => error && index === 0 ? 'failed' : 'pending')
  // Exactly one stage is active on screen: revealed stages are checked, later ones wait.
  const statuses = real.map((status, index): StageStatus => index < shown ? 'complete' : index > shown ? 'pending' : index < realDone ? 'running' : status)
  const active = Math.min(shown, STAGES.length - 1)
  const finished = Boolean(session) && step >= total && shown >= STAGES.length
  const baseline = target === '1.0.1' && shown === 0 && step < PLAN[target].scan
  const state: ScanState = error ? 'failed' : finished ? 'completed' : !session || baseline ? 'initializing' : active === 4 ? 'waiting' : 'scanning'
  const [title, description] = !sessionId ? ['진행 중인 검사가 없습니다.', '보안 검사 화면에서 새 검사를 시작해 주세요.']
    : error ? [failedTitle, error.message]
    : finished ? completedCopy
    : !session ? initializingCopy
    : baseline ? baselineCopy : stageCopy[active]
  const task = error ? STAGES[active][1] : finished ? '모든 단계 완료' : shown < realDone ? STAGES[active][1] : ACTIONS[step]?.[1] ?? STAGES[active][1]
  const running = Boolean(sessionId) && state !== 'completed' && state !== 'failed'
  const events = [
    ...(session?.events ?? []).map(({ at, type, detail }) => [clock(at), localizeEvent(detail, language), type, 'complete']),
    ...(running && session ? [['···', task, ACTIONS[step]?.[0] ?? '', 'waiting']] : []),
  ]
  const retry = () => { setError(null); setAttempt((value) => value + 1) }

  return <div className="workspace progress-workspace">
    <Sidebar active="Security Scan" className="progress-sidebar" />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Security Scan <b>/</b> Scan Progress</div><div className="ws-topbar-actions"><Link className="ws-button quiet" href="/security-scan"><Icon name="arrow" /> 검사 화면으로 돌아가기</Link><LanguageSwitcher /></div></header>
      <div className="ws-content progress-content">
        <div className="progress-heading"><div><div className="live-label"><i /> LIVE SECURITY ANALYSIS <span>LIVE DEMO</span></div><h1>{finished ? '보안 검사가 완료되었습니다.' : '보안 검사를 진행하고 있습니다.'}</h1><p>고정된 합성 fixture를 실제 Scanner · 검증자 서명 · Gateway로 검사합니다.</p></div><div className="scan-meta"><span><small>MCP TOOL</small><b>mail-mcp</b></span><span><small>VERSION</small><b>{target}</b></span><span><small>SCAN ID</small><b>{sessionId ? short(sessionId) : '—'}</b></span><span><small>STATUS</small><b className={state}>{state.toUpperCase()}</b></span></div></div>

        <section className={`pipeline-panel panel ${state === 'failed' ? 'has-failed' : ''}`}>
          <div className="pipeline-top"><div><small>STAGE-BASED PROGRESS</small><h2>{title}</h2><p>{description}</p></div><div className="stage-count"><b>{Math.min(shown + (finished ? 0 : 1), 6)}</b><span>/ 6 stages</span></div></div>
          <div className="stage-progress"><i style={{ width: `${finished ? 100 : (shown / STAGES.length) * 100}%` }} /></div>
          <div className="pipeline">{STAGES.map(([name, korean], index) => <div className={`pipeline-stage ${statuses[index]}`} key={name}><div className="pipeline-node">{statuses[index] === 'complete' ? <Icon name="check" /> : statuses[index] === 'failed' ? <Icon name="alert" /> : <span>{String(index + 1).padStart(2, '0')}</span>}</div><b>{name}</b><small>{korean}</small><em>{statuses[index] === 'running' ? 'IN PROGRESS' : statuses[index].toUpperCase()}</em></div>)}</div>
          <div className="demo-controls"><span>LOCAL_DEMO 원장을 사용합니다. 테스트넷 트랜잭션이 아닙니다.</span><div>{!sessionId ? <Link className="ws-button primary" href="/security-scan">보안 검사 시작</Link> : state === 'failed' ? (error?.expired ? <Link className="ws-button primary" href="/security-scan">새 검사 시작</Link> : <button className="ws-button primary" onClick={retry}>다시 시도</button>) : finished ? <Link className="ws-button primary" href={`/scan-results?session=${sessionId}`}>검사 결과 확인하기 <span>↗</span></Link> : <button className="ws-button primary" disabled>검사 진행 중…</button>}</div></div>
        </section>

        <section className="live-grid">
          <article className="current-analysis panel"><div className="live-panel-head"><div><small>CURRENT ANALYSIS</small><h2>{title}</h2></div><span className={state}><i /> {state}</span></div>
            <div className="analysis-body"><div className="analysis-orb"><span>{state === 'failed' ? <Icon name="alert" /> : <Icon name="scan" />}</span><i /><i /></div><div className="task-copy"><small>CURRENT TASK</small><h3>{task}</h3><p>{description}</p><div><span><small>PACKAGE</small><b>mail-mcp@{target}</b></span><span><small>POLICY</small><b>Static · AI · Sandbox</b></span><span><small>ENVIRONMENT</small><b>Local sandbox</b></span></div></div></div>
            <div className="inspection-strip"><span className={statuses[0] === 'complete' ? 'active' : ''}><i /> Manifest inspection</span><span className={statuses[1] === 'complete' ? 'active' : ''}><i /> Permission mapping</span><span className={statuses[3] === 'complete' ? 'active' : ''}><i /> Behavior analysis</span></div>
          </article>
          <aside className="security-events panel"><div className="live-panel-head"><div><small>SECURITY EVENTS</small><h2>Analysis activity</h2></div><span>{session?.events.length ?? 0} events</span></div>
            <div className="event-list">{events.map(([time, detail, type, status], index) => <div className={`event ${status}`} key={`${type}-${index}`}><i>{status === 'complete' ? <Icon name="check" /> : '···'}</i><div><b>{detail}</b><small>{type}</small></div><time>{time}</time></div>)}</div>
            <div className="events-note"><i /> 이벤트는 백엔드 검사 세션에서 받은 실제 기록입니다.</div>
          </aside>
        </section>
      </div>
    </main>
  </div>
}
