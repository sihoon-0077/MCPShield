'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { LanguageSwitcher } from './i18n'
import { Sidebar } from './workspace'
import { ScanTable } from './security-scan'
import { loadHistory, type ScanRecord } from './scan-session'

export function ScanHistory() {
  const [history, setHistory] = useState<ScanRecord[] | null>(null)
  useEffect(() => setHistory(loadHistory()), [])

  return <div className="workspace">
    <Sidebar active="History" />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> History</div><LanguageSwitcher /></header>
      <div className="ws-content">
        <div className="ws-heading"><div><p>SCAN ARCHIVE</p><h1>검사 기록</h1><span>이 브라우저에서 실행한 보안 검사 기록입니다.</span></div></div>
        <section className="recent panel">
          <div className="recent-head"><div><h2>Scan history</h2><p>Completed and interrupted security scans</p></div></div>
          {history?.length ? <ScanTable records={history} /> : <div className="scan-table">
            <div className="table-row table-labels"><span>TOOL</span><span>VERSION</span><span>STATUS</span><span>RISK</span><span>TIME</span><span /></div>
            <div className="history-empty">
              <strong>{history ? '아직 저장된 검사 기록이 없습니다.' : '검사 기록을 불러오는 중입니다.'}</strong>
              <p>보안 검사를 완료하면 이곳에서 결과 기록을 확인할 수 있습니다.</p>
              <Link className="ws-button primary" href="/security-scan">첫 검사 시작하기</Link>
            </div>
          </div>}
        </section>
      </div>
    </main>
  </div>
}
