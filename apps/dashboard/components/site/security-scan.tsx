'use client'

import { useState } from 'react'
import { LanguageSwitcher } from './i18n'

type IconName = 'grid' | 'scan' | 'result' | 'logs' | 'history' | 'settings' | 'plus' | 'play' | 'check' | 'alert' | 'chevron'

function AppIcon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>,
    scan: <><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /><circle cx="12" cy="12" r="3" /></>,
    result: <><path d="M5 3h14v18H5z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></>,
    logs: <><path d="M7 5h14M7 12h14M7 19h14" /><circle cx="3" cy="5" r=".5" fill="currentColor" /><circle cx="3" cy="12" r=".5" fill="currentColor" /><circle cx="3" cy="19" r=".5" fill="currentColor" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></>,
    plus: <path d="M12 5v14M5 12h14" />,
    play: <path d="m9 6 9 6-9 6V6Z" />,
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M12 3 2.8 20h18.4L12 3Z" /><path d="M12 9v5M12 17h.01" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
  }
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

const navItems: [IconName, string][] = [
  ['grid', 'Overview'], ['scan', 'Security Scan'], ['result', 'Scan Results'],
  ['logs', 'Validation Logs'], ['history', 'History'], ['settings', 'Settings'],
]

const progress = [
  ['Artifact Fetch', 'Source package acquired'],
  ['Static Analysis', '24 modules inspected'],
  ['AI Analysis', 'Behavior patterns evaluated'],
  ['Sandbox Check', 'Outbound action detected'],
  ['Validator Review', '2 of 3 validators agree'],
  ['Final Decision', 'Execution policy applied'],
]

const recent = [
  ['filesystem-mcp', '2.4.1', 'Blocked', 'High', '2 min ago'],
  ['github-connector', '1.8.0', 'Allowed', 'Low', '18 min ago'],
  ['web-search-tool', '3.1.2', 'Review', 'Medium', '1 hr ago'],
  ['notion-reader', '1.4.7', 'Allowed', 'Low', 'Yesterday'],
]

function Brand() {
  return <a className="ws-brand" href="/"><svg viewBox="0 0 28 28"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg><span>MCP<b>SHIELD</b></span></a>
}

export function SecurityScan() {
  const [scanned, setScanned] = useState(true)
  const runScan = () => setScanned(true)
  const startScan = () => window.location.assign('/scan-progress?scanId=MS-2841&tool=filesystem-mcp&version=2.4.1')

  return <div className="workspace">
    <aside className="ws-sidebar">
      <Brand />
      <div className="ws-environment"><i /> Demo Environment <AppIcon name="chevron" /></div>
      <nav aria-label="Workspace navigation">
        <small>WORKSPACE</small>
        {navItems.slice(0, 4).map(([icon, label]) => <a className={label === 'Security Scan' ? 'active' : ''} href="#" key={label}><AppIcon name={icon} /><span>{label}</span>{label === 'Validation Logs' && <b>8</b>}</a>)}
        <small>MANAGE</small>
        {navItems.slice(4).map(([icon, label]) => <a href="#" key={label}><AppIcon name={icon} /><span>{label}</span></a>)}
      </nav>
      <div className="ws-system"><span><i /> System Operational</span><small>Validators 3 / 3 online</small></div>
      <div className="ws-profile"><span>MK</span><div><b>Minjun Kim</b><small>Developer workspace</small></div><button aria-label="Profile menu">•••</button></div>
    </aside>

    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Security Scan</div><div><button className="ws-button quiet" onClick={runScan}><AppIcon name="play" /> Sample Demo</button><button className="ws-button primary"><AppIcon name="plus" /> New Scan</button><LanguageSwitcher /></div></header>
      <div className="ws-content">
        <div className="ws-heading"><div><p>SECURITY WORKSPACE</p><h1>보안 검사</h1><span>검사할 MCP 도구를 등록하고 위험 여부를 확인합니다.</span></div><div className="ws-session"><i /> Demo session <b>MS-2841</b></div></div>

        <section className="scan-layout">
          <div className="scan-form panel">
            <div className="panel-head"><div><span className="panel-index">01</span><h2>Scan target</h2><p>검사할 MCP 도구의 기본 정보를 입력하세요.</p></div><span className="draft">DRAFT</span></div>
            <div className="form-grid">
              <label><span>MCP TOOL NAME</span><input defaultValue="filesystem-mcp" /></label>
              <label><span>VERSION</span><input defaultValue="2.4.1" /></label>
              <label className="wide"><span>SOURCE / REPOSITORY</span><input defaultValue="github.com/example/filesystem-mcp" /></label>
              <label className="wide"><span>ARTIFACT HASH <i>OPTIONAL</i></span><input className="mono" defaultValue="sha256:8f42b72e6ac7...91dc" /></label>
            </div>
            <div className="target-meta"><span><small>TARGET TYPE</small><b>Remote repository</b></span><span><small>SCAN POLICY</small><b>Standard · v3.2</b></span><span><small>ESTIMATED TIME</small><b>~ 45 seconds</b></span></div>
            <div className="form-actions"><button className="ws-button quiet" onClick={runScan}>샘플 검사</button><button className="ws-button primary scan-start" onClick={startScan}><AppIcon name="scan" /> 보안 검사 시작</button></div>
          </div>

          <div className="scan-progress panel">
            <div className="panel-head"><div><span className="panel-index">02</span><h2>Scan progress</h2></div><span className="complete">COMPLETE</span></div>
            <div className="progress-list">{progress.map(([title, detail], index) => <div className={`progress-step ${index === 3 ? 'danger' : ''}`} key={title}><span>{index === 3 ? <AppIcon name="alert" /> : <AppIcon name="check" />}</span><div><b>{title}</b><small>{scanned ? detail : 'Waiting'}</small></div><em>{index === 3 ? 'FLAG' : 'DONE'}</em></div>)}</div>
            <div className="progress-total"><div><span>Analysis complete</span><b>100%</b></div><i><b /></i></div>
          </div>

          <aside className="result-summary panel">
            <div className="panel-head"><div><span className="panel-index">03</span><h2>Result summary</h2></div></div>
            <div className="risk-block"><small>RISK LEVEL</small><strong>HIGH</strong><span>8.6 <i>/ 10</i></span><div><b /></div></div>
            <div className="summary-item"><small>SUSPICIOUS BEHAVIOR</small><p>Unauthorized outbound action detected</p><span className="danger-tag">External access</span></div>
            <div className="summary-item"><small>VALIDATOR AGREEMENT</small><p><b>2 / 3</b> validators recommend blocking</p><div className="validator-dots"><i /><i /><i /></div></div>
            <div className="decision-block"><small>FINAL EXECUTION DECISION</small><div><span><AppIcon name="alert" /></span><strong>BLOCKED</strong></div><p>실행 전에 안전하게 차단되었습니다.</p></div>
            <button className="result-link">View full scan report <span>↗</span></button>
          </aside>
        </section>

        <section className="recent panel">
          <div className="recent-head"><div><h2>Recent scans</h2><p>Latest activity in this workspace</p></div><button>View all history <span>↗</span></button></div>
          <div className="scan-table">
            <div className="table-row table-labels"><span>TOOL</span><span>VERSION</span><span>STATUS</span><span>RISK</span><span>TIME</span><span /></div>
            {recent.map(([tool, version, status, risk, time]) => <div className="table-row" key={tool}><span className="tool-name"><i>{tool[0].toUpperCase()}</i><b>{tool}</b></span><span className="mono">{version}</span><span><b className={`status ${status.toLowerCase()}`}>{status}</b></span><span className={`risk ${risk.toLowerCase()}`}>{risk}</span><span>{time}</span><button aria-label={`Open ${tool}`}><AppIcon name="chevron" /></button></div>)}
          </div>
        </section>
      </div>
    </main>
  </div>
}
