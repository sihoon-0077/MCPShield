import Link from 'next/link'
import { LanguageSwitcher } from './i18n'

const items = [
  ['Security Scan', '/security-scan'],
  ['Scan Results', '/scan-results'],
  ['History', '/history'],
]

function Brand() {
  return <Link className="ws-brand" href="/">
    <svg viewBox="0 0 28 28"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg>
    <span>MCP<b>SHIELD</b></span>
  </Link>
}

export function ScanHistory() {
  return <div className="workspace">
    <aside className="ws-sidebar">
      <Brand />
      <div className="ws-environment"><i /> Demo Environment</div>
      <nav aria-label="Workspace navigation">
        <small>WORKSPACE</small>
        {items.map(([label, href]) => <Link className={label === 'History' ? 'active' : ''} href={href} key={label}><span>{label}</span></Link>)}
      </nav>
      <div className="ws-system"><span><i /> System Operational</span><small>Validators 3 / 3 online</small></div>
      <div className="ws-profile"><span>MK</span><div><b>Minjun Kim</b><small>Developer workspace</small></div><button aria-label="Profile menu">•••</button></div>
    </aside>
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> History</div><LanguageSwitcher /></header>
      <div className="ws-content">
        <div className="ws-heading"><div><p>SCAN ARCHIVE</p><h1>검사 기록</h1><span>이 워크스페이스에서 실행한 보안 검사 기록입니다.</span></div></div>
        <section className="recent panel">
          <div className="recent-head"><div><h2>Scan history</h2><p>Completed and interrupted security scans</p></div></div>
          <div className="scan-table">
            <div className="table-row table-labels"><span>TOOL</span><span>VERSION</span><span>STATUS</span><span>RISK</span><span>TIME</span><span /></div>
            <div className="history-empty">
              <strong>아직 저장된 검사 기록이 없습니다.</strong>
              <p>보안 검사를 완료하면 이곳에서 결과 기록을 확인할 수 있습니다.</p>
              <Link className="ws-button primary" href="/security-scan">첫 검사 시작하기</Link>
            </div>
          </div>
        </section>
      </div>
    </main>
  </div>
}
