'use client'

import Link from 'next/link'
import { LanguageSwitcher } from './i18n'
import { Sidebar } from './workspace'
import { useBoard, useSession } from './v3-api'
import { LoginRequired, RunsTable } from './v3-views'

// Every operator scan this tenant has in the V3 operator API, with the validator round each one opened. Nothing is kept in the browser.
export function ScanHistory() {
  const session = useSession()
  const signedIn = session.status === 'signed-in'
  const { board, error } = useBoard(signedIn)

  return <div className="workspace">
    <Sidebar active="History" />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> 검사 기록</div><LanguageSwitcher /></header>
      <div className="ws-content">
        <div className="ws-heading"><div><p>SCAN ARCHIVE</p><h1>검사 기록</h1><span>운영 API에 저장된 이 조직의 검사 기록입니다. 브라우저에 따로 저장하지 않습니다.</span></div></div>
        {(session.status === 'error' || error) && <p className="scan-error v3-banner" role="alert">{session.status === 'error' ? session.message : error}</p>}
        <section className="recent panel">
          <div className="recent-head"><div><h2>전체 검사</h2><p>끝난 운영사 검사마다 그 유효기간으로 검증자 라운드가 열립니다. 재사용된 결과는 새 라운드를 열지 않습니다.</p></div></div>
          {session.status === 'signed-out' ? <div className="scan-table"><div className="history-empty"><LoginRequired /></div></div>
            : board?.scans.length ? <RunsTable board={board} />
            : <div className="scan-table">
              <div className="history-empty">
                <strong>{board ? '아직 검사 기록이 없습니다.' : session.status === 'loading' ? '운영 API 세션을 확인하고 있습니다.' : '검사 기록을 불러오는 중입니다.'}</strong>
                {board && <Link className="ws-button primary" href="/security-scan">첫 검사 시작하기</Link>}
              </div>
            </div>}
        </section>
      </div>
    </main>
  </div>
}
