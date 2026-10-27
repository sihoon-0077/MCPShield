'use client'

import { useState } from 'react'
import { LanguageSwitcher } from './i18n'

type ScanState = 'initializing' | 'scanning' | 'waiting' | 'completed' | 'failed'
type IconName = 'grid' | 'scan' | 'result' | 'logs' | 'history' | 'settings' | 'check' | 'alert' | 'chevron' | 'arrow'

function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>,
    scan: <><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /><circle cx="12" cy="12" r="3" /></>,
    result: <><path d="M5 3h14v18H5z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></>,
    logs: <><path d="M7 5h14M7 12h14M7 19h14" /><circle cx="3" cy="5" r=".5" fill="currentColor" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M5 5l2 2m10-2-2 2m2 10-2-2M5 19l2-2M12 2v3m0 14v3M2 12h3m14 0h3" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M12 3 2.8 20h18.4L12 3Z" /><path d="M12 9v5M12 17h.01" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
    arrow: <path d="m5 12 6-6m-6 6 6 6M5 12h14" />,
  }
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

const nav: [IconName, string, string][] = [
  ['grid', 'Overview', '#'], ['scan', 'Security Scan', '/security-scan'], ['result', 'Scan Results', '/scan-results'],
  ['logs', 'Validation Logs', '#'], ['history', 'History', '#'], ['settings', 'Settings', '#'],
]

const stages = [
  ['Artifact Fetch', '패키지 정보 수집'],
  ['Static Analysis', '정적 보안 분석'],
  ['AI Analysis', 'AI 위험 분석'],
  ['Sandbox Check', '격리 환경 검사'],
  ['Validator Review', '검증자 판정'],
  ['Final Decision', '최종 실행 결정'],
]

const stateCopy: Record<ScanState, [string, string]> = {
  initializing: ['검사 환경을 준비하고 있습니다.', '도구 정보와 분석 정책을 확인하는 중입니다.'],
  scanning: ['AI 위험 분석', '도구의 선언된 기능과 실제 동작 패턴을 비교하고 있습니다.'],
  waiting: ['검증자 판정 대기', '독립 검증자의 분석 결과를 기다리고 있습니다.'],
  completed: ['검사가 완료되었습니다.', '모든 분석 단계와 검증자 판정이 완료되었습니다.'],
  failed: ['검사를 완료하지 못했습니다.', '분석 환경에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.'],
}

function Sidebar() {
  return <aside className="ws-sidebar progress-sidebar">
    <a className="ws-brand" href="/"><svg viewBox="0 0 28 28"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg><span>MCP<b>SHIELD</b></span></a>
    <div className="ws-environment"><i /> Demo Environment <Icon name="chevron" /></div>
    <nav aria-label="Workspace navigation"><small>WORKSPACE</small>
      {nav.slice(0, 4).map(([icon, label, href]) => <a className={label === 'Security Scan' ? 'active' : ''} href={href} key={label}><Icon name={icon} /><span>{label}</span></a>)}
      <small>MANAGE</small>{nav.slice(4).map(([icon, label, href]) => <a href={href} key={label}><Icon name={icon} /><span>{label}</span></a>)}
    </nav>
    <div className="ws-system"><span><i /> System Operational</span><small>Validators 3 / 3 online</small></div>
    <div className="ws-profile"><span>MK</span><div><b>Minjun Kim</b><small>Developer workspace</small></div><button aria-label="Profile menu">•••</button></div>
  </aside>
}

export function ScanProgress({ scanId, tool, version }: { scanId: string; tool: string; version: string }) {
  const [state, setState] = useState<ScanState>('scanning')
  const [stage, setStage] = useState(2)

  const advance = () => {
    if (stage < 4) { const next = stage + 1; setStage(next); setState(next === 4 ? 'waiting' : 'scanning') }
    else { setStage(5); setState('completed') }
  }
  const retry = () => { setStage(0); setState('initializing') }
  const statusFor = (index: number) => state === 'failed' && index === stage ? 'failed' : index < stage ? 'complete' : index === stage ? (state === 'completed' ? 'complete' : 'running') : 'pending'
  const events = [
    ['14:32:04', 'Package metadata retrieved', 'complete'],
    ['14:32:05', 'Artifact integrity checked', 'complete'],
    ...(stage >= 2 ? [['14:32:07', 'Static analysis completed', 'complete']] : []),
    ...(state === 'waiting' || state === 'completed' ? [['Pending', 'Validator review requested', 'waiting']] : []),
  ]

  return <div className="workspace progress-workspace">
    <Sidebar />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Security Scan <b>/</b> Scan Progress</div><div className="ws-topbar-actions"><a className="ws-button quiet" href="/security-scan"><Icon name="arrow" /> 검사 화면으로 돌아가기</a><LanguageSwitcher /></div></header>
      <div className="ws-content progress-content">
        <div className="progress-heading"><div><div className="live-label"><i /> LIVE SECURITY ANALYSIS <span>DEMO MODE</span></div><h1>보안 검사를 진행하고 있습니다.</h1><p>AI 도구의 위험 요소를 분석하고 검증 결과를 확인하고 있습니다.</p></div><div className="scan-meta"><span><small>MCP TOOL</small><b>{tool}</b></span><span><small>VERSION</small><b>{version}</b></span><span><small>SCAN ID</small><b>{scanId}</b></span><span><small>STATUS</small><b className={state}>{state.toUpperCase()}</b></span></div></div>

        <section className={`pipeline-panel panel ${state === 'failed' ? 'has-failed' : ''}`}>
          <div className="pipeline-top"><div><small>STAGE-BASED PROGRESS</small><h2>{stateCopy[state][0]}</h2><p>{stateCopy[state][1]}</p></div><div className="stage-count"><b>{Math.min(stage + 1, 6)}</b><span>/ 6 stages</span></div></div>
          <div className="stage-progress"><i style={{ width: `${state === 'completed' ? 100 : (stage / 5) * 100}%` }} /></div>
          <div className="pipeline">{stages.map(([name, korean], index) => <div className={`pipeline-stage ${statusFor(index)}`} key={name}><div className="pipeline-node">{statusFor(index) === 'complete' ? <Icon name="check" /> : statusFor(index) === 'failed' ? <Icon name="alert" /> : <span>{String(index + 1).padStart(2, '0')}</span>}</div><b>{name}</b><small>{korean}</small><em>{statusFor(index) === 'running' ? 'IN PROGRESS' : statusFor(index).toUpperCase()}</em></div>)}</div>
          <div className="demo-controls"><span>실제 백엔드 연결 없이 단계별 UI를 확인하는 데모입니다.</span><div>{state !== 'failed' && state !== 'completed' && <button className="ws-button quiet fail-demo" onClick={() => setState('failed')}>실패 상태 보기</button>}{state === 'failed' ? <button className="ws-button primary" onClick={retry}>다시 시도</button> : state === 'completed' ? <a className="ws-button primary" href={`/scan-results?scanId=${scanId}`}>검사 결과 확인하기 <span>↗</span></a> : <button className="ws-button primary" onClick={advance}>다음 데모 단계</button>}</div></div>
        </section>

        <section className="live-grid">
          <article className="current-analysis panel"><div className="live-panel-head"><div><small>CURRENT ANALYSIS</small><h2>{stateCopy[state][0]}</h2></div><span className={state}><i /> {state}</span></div>
            <div className="analysis-body"><div className="analysis-orb"><span>{state === 'failed' ? <Icon name="alert" /> : <Icon name="scan" />}</span><i /><i /></div><div className="task-copy"><small>CURRENT TASK</small><h3>{stages[stage][1]}</h3><p>{stateCopy[state][1]}</p><div><span><small>PACKAGE</small><b>{tool}@{version}</b></span><span><small>POLICY</small><b>Standard v3.2</b></span><span><small>ENVIRONMENT</small><b>Isolated sandbox</b></span></div></div></div>
            <div className="inspection-strip"><span><i /> Manifest inspection</span><span><i /> Permission mapping</span><span className={stage >= 2 ? 'active' : ''}><i /> Behavior analysis</span></div>
          </article>
          <aside className="security-events panel"><div className="live-panel-head"><div><small>SECURITY EVENTS</small><h2>Analysis activity</h2></div><span>{events.length} events</span></div>
            <div className="event-list">{events.map(([time, title, status], index) => <div className={`event ${status}`} key={`${title}-${index}`}><i>{status === 'complete' ? <Icon name="check" /> : '···'}</i><div><b>{title}</b><small>Demo scan activity</small></div><time>{time}</time></div>)}</div>
            <div className="events-note"><i /> 이벤트는 데모 단계가 진행될 때만 추가됩니다.</div>
          </aside>
        </section>
      </div>
    </main>
  </div>
}
