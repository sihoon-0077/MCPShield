'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { LanguageSwitcher } from './i18n'
import { Icon, Sidebar } from './workspace'
import { PLAN, STAGES, ago, createSession, errorText, loadHistory, reportOf, saveRecord, severityClass, short, type ScanRecord, type ScanStatus, type Target } from './scan-session'

const statusLabel: Record<ScanStatus, [string, string]> = {
  BLOCKED: ['Blocked', 'blocked'], ALLOWED: ['Allowed', 'allowed'], RUNNING: ['Running', 'review'], FAILED: ['Failed', 'review'],
}

function stageDetail(report: ReturnType<typeof reportOf>, index: number): [string, boolean] {
  const count = (stage: string) => report.byStage(stage).length
  const found = (stage: string): [string, boolean] => [count(stage) ? `${count(stage)} findings` : 'No findings', count(stage) > 0]
  if (index === 0) return ['Digest & tool surface computed', false]
  if (index === 1) return found('STATIC')
  if (index === 2) return found('AI')
  if (index === 3) return found('SANDBOX')
  if (index === 4) return [report.failVotes ? `${report.failVotes} / 3 unsafe` : `${report.votes.length} / 3 approved`, report.failVotes > 0]
  return report.execution?.decision === 'BLOCK' ? ['Execution blocked', true] : ['Executed in Gateway', false]
}

export function ScanTable({ records }: { records: ScanRecord[] }) {
  const router = useRouter()
  return <div className="scan-table">
    <div className="table-row table-labels"><span>TOOL</span><span>VERSION</span><span>STATUS</span><span>RISK</span><span>TIME</span><span /></div>
    {records.map((record) => {
      const report = reportOf(record)
      const [label, tone] = statusLabel[record.status]
      const href = record.status === 'RUNNING' ? `/scan-progress?session=${record.sessionId}&target=${record.target}` : `/scan-results?session=${record.sessionId}`
      return <div className="table-row" key={record.sessionId}><span className="tool-name"><i>M</i><b>mail-mcp</b></span><span className="mono">{record.target}</span><span><b className={`status ${tone}`}>{label}</b></span><span className={`risk ${severityClass(report.severity)}`}>{report.severity === 'NONE' ? 'None' : report.severity}</span><span>{ago(record.updatedAt)}</span><button aria-label={`Open ${short(record.sessionId)}`} onClick={() => router.push(href)}><Icon name="chevron" /></button></div>
    })}
  </div>
}

export function SecurityScan() {
  const router = useRouter()
  const [target, setTarget] = useState<Target>('1.0.1')
  const [history, setHistory] = useState<ScanRecord[]>([])
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => setHistory(loadHistory()), [])

  const start = async (version: Target) => {
    setStarting(true); setError(null)
    try {
      const session = await createSession()
      const now = new Date().toISOString()
      saveRecord({ sessionId: session.sessionId, target: version, status: 'RUNNING', startedAt: now, updatedAt: now, baselineFindingCount: null, session })
      router.push(`/scan-progress?session=${session.sessionId}&target=${version}`)
    } catch (cause) {
      setError(errorText(cause)); setStarting(false)
    }
  }

  const latest = history.find((record) => record.status === 'ALLOWED' || record.status === 'BLOCKED')
  const report = latest && reportOf(latest)
  const blocked = report?.execution?.decision === 'BLOCK'

  return <div className="workspace">
    <Sidebar active="Security Scan" />

    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Security Scan</div><div><button className="ws-button quiet" onClick={() => start('1.0.1')} disabled={starting}><Icon name="play" /> Sample Demo</button><button className="ws-button primary" onClick={() => { setTarget('1.0.1'); setError(null) }}><Icon name="plus" /> New Scan</button><LanguageSwitcher /></div></header>
      <div className="ws-content">
        <div className="ws-heading"><div><p>SECURITY WORKSPACE</p><h1>보안 검사</h1><span>검사할 MCP 도구를 등록하고 위험 여부를 확인합니다.</span></div><div className="ws-session"><i /> Demo session <b>{latest ? short(latest.sessionId) : '—'}</b></div></div>

        <section className="scan-layout">
          <div className="scan-form panel">
            <div className="panel-head"><div><span className="panel-index">01</span><h2>Scan target</h2><p>검사할 버전을 선택하세요. 공개 데모는 검토된 고정 fixture만 실행합니다.</p></div><span className="draft">DRAFT</span></div>
            <div className="form-grid">
              <label><span>MCP TOOL NAME</span><input value="mail-mcp" readOnly /></label>
              <label><span>VERSION</span><select value={target} onChange={(event) => setTarget(event.target.value as Target)}><option value="1.0.1">1.0.1 · 후보</option><option value="1.0.0">1.0.0 · 기준</option></select></label>
              <label className="wide"><span>SOURCE / REPOSITORY</span><input value={`demo/fixtures/mail-mcp-${target}`} readOnly /></label>
              <label className="wide"><span>ARTIFACT HASH <i>OPTIONAL</i></span><input className="mono" placeholder="sha256 · computed by the Scanner during the scan" readOnly /></label>
            </div>
            <div className="target-meta"><span><small>TARGET TYPE</small><b>Synthetic fixture</b></span><span><small>SCAN POLICY</small><b>Static · AI · Sandbox</b></span><span><small>ESTIMATED TIME</small><b>~ {PLAN[target].total + 1} seconds</b></span></div>
            {error && <p className="scan-error" role="alert">{error}</p>}
            <div className="form-actions"><button className="ws-button quiet" onClick={() => start('1.0.1')} disabled={starting}>샘플 검사</button><button className="ws-button primary scan-start" onClick={() => start(target)} disabled={starting}><Icon name="scan" /> {starting ? '세션 준비 중…' : '보안 검사 시작'}</button></div>
          </div>

          <div className="scan-progress panel">
            <div className="panel-head"><div><span className="panel-index">02</span><h2>Scan progress</h2></div><span className="complete">{report ? 'COMPLETE' : 'IDLE'}</span></div>
            <div className="progress-list">{STAGES.map(([title], index) => {
              const [detail, flagged] = report ? stageDetail(report, index) : ['Waiting', false]
              return <div className={`progress-step ${flagged ? 'danger' : ''}`} key={title}><span>{flagged ? <Icon name="alert" /> : <Icon name="check" />}</span><div><b>{title}</b><small>{detail}</small></div><em>{!report ? 'WAIT' : flagged ? 'FLAG' : 'DONE'}</em></div>
            })}</div>
            <div className="progress-total"><div><span>Analysis complete</span><b>{report ? '100%' : '0%'}</b></div><i><b style={report ? undefined : { width: 0 }} /></i></div>
          </div>

          <aside className="result-summary panel">
            <div className="panel-head"><div><span className="panel-index">03</span><h2>Result summary</h2></div></div>
            <div className="risk-block"><small>RISK LEVEL</small><strong className={report?.severityLevel ? '' : 'none'}>{report ? report.severity : '—'}</strong><span>{report?.findings.length ?? 0} <i>findings</i></span><div><b style={{ width: `${(report?.severityLevel ?? 0) * 25}%` }} /></div></div>
            <div className="summary-item"><small>SUSPICIOUS BEHAVIOR</small><p>{report?.findings[0]?.message ?? (report ? 'No suspicious behavior detected' : '검사를 시작하면 결과가 표시됩니다.')}</p>{report?.findings[0] && <span className="danger-tag">{report.findings[0].code}</span>}</div>
            <div className="summary-item"><small>VALIDATOR AGREEMENT</small><p><b>{report ? (report.failVotes || report.votes.length) : 0} / 3</b> {report?.failVotes ? 'validators recommend blocking' : 'validators approved'}</p><div className="validator-dots">{[0, 1, 2].map((index) => <i key={index} className={report?.votes[index] ? (report.votes[index].decision === 'FAIL' ? 'fail' : 'pass') : 'none'} />)}</div></div>
            <div className={`decision-block ${report && !blocked ? 'allowed' : ''}`}><small>FINAL EXECUTION DECISION</small><div><span><Icon name={report && !blocked ? 'check' : 'alert'} /></span><strong>{report ? (blocked ? 'BLOCKED' : 'ALLOWED') : 'WAITING'}</strong></div><p>{report ? (blocked ? '실행 전에 안전하게 차단되었습니다.' : '검증된 릴리스만 Gateway에서 실행되었습니다.') : '아직 완료된 검사가 없습니다.'}</p></div>
            {latest && <Link className="result-link" href={`/scan-results?session=${latest.sessionId}`}>View full scan report <span>↗</span></Link>}
          </aside>
        </section>

        <section className="recent panel">
          <div className="recent-head"><div><h2>Recent scans</h2><p>Latest activity in this workspace</p></div><button onClick={() => router.push('/history')}>View all history <span>↗</span></button></div>
          {history.length ? <ScanTable records={history.slice(0, 4)} /> : <div className="scan-table"><div className="history-empty"><strong>아직 저장된 검사 기록이 없습니다.</strong><p>보안 검사를 완료하면 이곳에서 결과 기록을 확인할 수 있습니다.</p></div></div>}
        </section>
      </div>
    </main>
  </div>
}
