import { LanguageSwitcher } from './i18n'

type IconName = 'grid' | 'scan' | 'result' | 'logs' | 'history' | 'settings' | 'download' | 'refresh' | 'check' | 'alert' | 'chevron'

function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>,
    scan: <><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /><circle cx="12" cy="12" r="3" /></>,
    result: <><path d="M5 3h14v18H5z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></>,
    logs: <><path d="M7 5h14M7 12h14M7 19h14" /><circle cx="3" cy="5" r=".5" fill="currentColor" /><circle cx="3" cy="12" r=".5" fill="currentColor" /><circle cx="3" cy="19" r=".5" fill="currentColor" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M19 15a2 2 0 0 0 .4 2l-2.8 2.8a2 2 0 0 0-2-.4A2 2 0 0 0 13 21h-4a2 2 0 0 0-1.6-1.6 2 2 0 0 0-2 .4L2.6 17a2 2 0 0 0 .4-2A2 2 0 0 0 1 13V9a2 2 0 0 0 2-1.6 2 2 0 0 0-.4-2l2.8-2.8a2 2 0 0 0 2 .4A2 2 0 0 0 9 1h4a2 2 0 0 0 1.6 2 2 2 0 0 0 2-.4l2.8 2.8a2 2 0 0 0-.4 2A2 2 0 0 0 21 9v4a2 2 0 0 0-2 2Z" /></>,
    download: <><path d="M12 3v12m0 0 5-5m-5 5-5-5" /><path d="M5 20h14" /></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.1 8A7 7 0 0 1 18 6l2 2M18 16a7 7 0 0 1-12 2l-2-2" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M12 3 2.8 20h18.4L12 3Z" /><path d="M12 9v5M12 17h.01" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
  }
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

const nav: [IconName, string, string][] = [
  ['grid', 'Overview', '#'], ['scan', 'Security Scan', '/security-scan'], ['result', 'Scan Results', '/scan-results'],
  ['logs', 'Validation Logs', '#'], ['history', 'History', '#'], ['settings', 'Settings', '#'],
]

const stages = [
  ['Artifact Fetch', 'Package secured', 'complete'],
  ['Static Analysis', '24 modules inspected', 'complete'],
  ['AI Analysis', 'Anomaly identified', 'warning'],
  ['Sandbox Check', 'Outbound call detected', 'danger'],
  ['Validator Review', '2 / 3 unsafe', 'warning'],
  ['Final Decision', 'Execution blocked', 'blocked'],
]

const findings = [
  ['CRITICAL', 'Unauthorized outbound access', 'External request to an unapproved endpoint was attempted.', 'Sandbox · 14:32:08'],
  ['HIGH', 'Suspicious package behavior', 'Runtime behavior differs from the declared tool capability.', 'AI Analysis · 14:32:07'],
  ['HIGH', 'Policy violation', 'Network permission exceeds the active execution policy.', 'Static · 14:32:06'],
  ['MEDIUM', 'Unexpected tool action', 'A secondary process was spawned during evaluation.', 'Sandbox · 14:32:08'],
  ['MEDIUM', 'Elevated execution attempt', 'Tool requested access outside the allowed workspace.', 'Validator · 14:32:09'],
]

function Sidebar() {
  return <aside className="ws-sidebar">
    <a className="ws-brand" href="/"><svg viewBox="0 0 28 28"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg><span>MCP<b>SHIELD</b></span></a>
    <div className="ws-environment"><i /> Demo Environment <Icon name="chevron" /></div>
    <nav aria-label="Workspace navigation">
      <small>WORKSPACE</small>
      {nav.slice(0, 4).map(([icon, label, href]) => <a className={label === 'Scan Results' ? 'active' : ''} href={href} key={label}><Icon name={icon} /><span>{label}</span>{label === 'Validation Logs' && <b>8</b>}</a>)}
      <small>MANAGE</small>
      {nav.slice(4).map(([icon, label, href]) => <a href={href} key={label}><Icon name={icon} /><span>{label}</span></a>)}
    </nav>
    <div className="ws-system"><span><i /> System Operational</span><small>Validators 3 / 3 online</small></div>
    <div className="ws-profile"><span>MK</span><div><b>Minjun Kim</b><small>Developer workspace</small></div><button aria-label="Profile menu">•••</button></div>
  </aside>
}

export function ScanResults() {
  return <div className="workspace results-workspace">
    <Sidebar />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Scan Results</div><div><button className="ws-button quiet"><Icon name="download" /> Export Report</button><a className="ws-button primary" href="/security-scan"><Icon name="refresh" /> Re-run Scan</a><LanguageSwitcher /></div></header>
      <div className="ws-content results-content">
        <div className="ws-heading"><div><p>INVESTIGATION REPORT</p><h1>검사 결과</h1><span>filesystem-mcp 2.4.1의 보안 분석 결과입니다.</span></div><div className="ws-session"><i /> Scan complete <b>MS-2841</b></div></div>

        <section className="metric-row">
          <article className="metric-card verdict"><small>FINAL VERDICT</small><div><Icon name="alert" /><strong>BLOCKED</strong></div><p>실행 차단 · Execution prevented</p></article>
          <article className="metric-card"><small>RISK SCORE</small><strong>84 <i>/ 100</i></strong><p>높음 · High Risk</p><div className="metric-bar"><b /></div></article>
          <article className="metric-card"><small>DETECTED ISSUES</small><strong>7 <i>Findings</i></strong><p><span className="red-dot" /> 주요 위험 3건</p></article>
          <article className="metric-card"><small>VALIDATOR CONSENSUS</small><strong>2 <i>/ 3</i></strong><p>실행 차단 권고</p><div className="mini-validators"><i /><i /><i /></div></article>
        </section>

        <section className="analysis-grid">
          <article className="analysis-map panel">
            <div className="report-panel-head"><div><small>ANALYSIS FLOW</small><h2>Security investigation map</h2></div><span>Completed in 42.8s</span></div>
            <div className="flow-canvas">
              <div className="flow-line" />
              {stages.map(([title, detail, status], index) => <div className={`flow-node ${status}`} key={title}>
                <span className="node-number">0{index + 1}</span>
                <div className="node-core">{status === 'danger' || status === 'blocked' ? <Icon name="alert" /> : <Icon name="check" />}</div>
                <b>{title}</b><small>{detail}</small>
                {status === 'danger' && <em>OUTBOUND / 443</em>}
              </div>)}
              <div className="signal-card signal-one"><small>BEHAVIOR SIGNAL</small><b>Undeclared network request</b><span>Confidence 96.4%</span></div>
              <div className="signal-card signal-two"><small>POLICY ENGINE</small><b>NET-EXT-04 violated</b><span>Enforcement: block</span></div>
            </div>
            <div className="map-legend"><span><i className="ok" /> Verified</span><span><i className="warn" /> Review</span><span><i className="bad" /> Risk detected</span><b>MS-2841 · Standard policy v3.2</b></div>
          </article>

          <aside className="investigation-detail panel">
            <div className="report-panel-head"><div><small>SCAN SUBJECT</small><h2>Result details</h2></div></div>
            <div className="tool-identity"><span>F</span><div><b>filesystem-mcp</b><small>Version 2.4.1</small></div><em>HIGH RISK</em></div>
            <dl><div><dt>Scan ID</dt><dd>MS-2841</dd></div><div><dt>Repository</dt><dd>github.com/example/filesystem-mcp</dd></div><div><dt>Severity</dt><dd className="danger-text">High · 8.4</dd></div><div><dt>Validator notes</dt><dd>2 of 3 validators marked this release as unsafe.</dd></div></dl>
            <div className="reason-card"><small>PRIMARY REASON</small><p>허용되지 않은 외부 접근 시도가 감지되었습니다.</p><span>Detected during Sandbox Check</span></div>
            <div className="final-decision"><small>EXECUTION DECISION</small><div><span><Icon name="alert" /></span><strong>BLOCKED</strong></div><p>Policy engine prevented tool execution.</p></div>
          </aside>
        </section>

        <section className="lower-results">
          <article className="findings-panel panel">
            <div className="report-panel-head"><div><small>DETECTED ISSUES</small><h2>Findings</h2></div><button>7 total <span>↗</span></button></div>
            <div className="finding-list">{findings.map(([severity, title, text, meta], index) => <div className="finding" key={title}><span className={`severity ${severity.toLowerCase()}`}>{severity}</span><div><b>{title}</b><p>{text}</p></div><small>{meta}</small><button aria-label={`Open finding ${index + 1}`}><Icon name="chevron" /></button></div>)}</div>
          </article>
          <article className="evidence-panel panel">
            <div className="report-panel-head"><div><small>TRACE EVIDENCE</small><h2>Evidence & logs</h2></div><span>UTC +09:00</span></div>
            <div className="log-list">
              <div><time>14:32:05.184</time><span className="log-info">INFO</span><p>artifact.fetch completed <b>sha256:8f42...91dc</b></p></div>
              <div><time>14:32:07.442</time><span className="log-warn">WARN</span><p>ai.analysis flagged suspicious behavior</p></div>
              <div className="log-danger"><time>14:32:08.109</time><span>ALERT</span><p>outbound request detected <b>host: external-api.io:443</b></p></div>
              <div><time>14:32:09.012</time><span className="log-warn">WARN</span><p>validator.02 marked release high risk</p></div>
              <div><time>14:32:09.386</time><span className="log-block">BLOCK</span><p>execution policy blocked release <b>NET-EXT-04</b></p></div>
            </div>
            <button className="view-raw">View raw validation logs <span>↗</span></button>
          </article>
        </section>
      </div>
    </main>
  </div>
}
