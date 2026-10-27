'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { LanguageSwitcher } from './i18n'
import { Icon, Sidebar } from './workspace'
import { STAGES, clock, findRecord, getSession, loadHistory, recordFromSession, reportOf, short, stageName, type ScanRecord } from './scan-session'

function logLevel(type: string, detail: string): [string, string, string] {
  if (type === 'BLOCK_BEFORE_SPAWN') return ['BLOCK', '', 'log-block']
  if (type === 'QUORUM_REACHED' && detail.includes('REVOKED')) return ['ALERT', 'log-danger', '']
  if ((type === 'SCAN_COMPLETED' && detail.includes('FAILED')) || (type === 'VALIDATOR_VOTE' && detail.startsWith('FAIL'))) return ['WARN', '', 'log-warn']
  return ['INFO', '', 'log-info']
}

function timezone() {
  const offset = -new Date().getTimezoneOffset()
  const hours = String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0')
  return `UTC ${offset < 0 ? '-' : '+'}${hours}:${String(Math.abs(offset) % 60).padStart(2, '0')}`
}

function Shell({ children }: { children: React.ReactNode }) {
  return <div className="workspace results-workspace">
    <Sidebar active="Scan Results" />
    <main className="ws-main">{children}</main>
  </div>
}

function Report({ record }: { record: ScanRecord }) {
  const { session, sessionId, target } = record
  const report = reportOf(record)
  const { execution, findings, votes, failVotes, release, severity, stages } = report
  const blocked = execution?.decision === 'BLOCK'
  const verdict = execution ? (blocked ? 'BLOCKED' : 'ALLOWED') : record.status === 'FAILED' ? 'FAILED' : 'RUNNING'
  const major = findings.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH').length
  const seconds = execution ? ((Date.parse(execution.at) - Date.parse(session.createdAt)) / 1000).toFixed(1) : null
  const top = findings[0]
  const behavior = report.byStage('AI')[0] ?? top
  const count = (stage: string) => report.byStage(stage).length
  const flow: [string, string, string][] = STAGES.map(([title], index) => {
    if (stages[index] !== 'complete') return [title, stages[index] === 'failed' ? 'Interrupted' : 'Not run', '']
    if (index === 0) return [title, 'Digest computed', 'complete']
    if (index <= 3) {
      const stage = ['STATIC', 'AI', 'SANDBOX'][index - 1]
      return [title, count(stage) ? `${count(stage)} findings` : 'No findings', count(stage) ? (index === 3 ? 'danger' : 'warning') : 'complete']
    }
    if (index === 4) return [title, failVotes ? `${failVotes} / 3 unsafe` : `${votes.length} / 3 approved`, failVotes ? 'warning' : 'complete']
    return [title, blocked ? 'Execution blocked' : 'Executed in Gateway', blocked ? 'blocked' : 'complete']
  })

  const exportReport = () => {
    const body = { exportedAt: new Date().toISOString(), source: session.source, synthetic: session.synthetic, ledgerMode: session.ledgerMode, sessionId, releaseId: report.releaseId, verdict, release, findings, votes, execution, events: session.events }
    const url = URL.createObjectURL(new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url; link.download = `mcpshield-${report.releaseId}-${short(sessionId)}.json`; link.click()
    URL.revokeObjectURL(url)
  }

  return <>
    <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Scan Results</div><div><button className="ws-button quiet" onClick={exportReport}><Icon name="download" /> Export Report</button><Link className="ws-button primary" href="/security-scan"><Icon name="refresh" /> Re-run Scan</Link><LanguageSwitcher /></div></header>
    <div className="ws-content results-content">
      <div className="ws-heading"><div><p>INVESTIGATION REPORT</p><h1>검사 결과</h1><span>{report.releaseId}의 보안 분석 결과입니다.</span></div><div className="ws-session"><i /> {execution ? 'Scan complete' : verdict} <b>{short(sessionId)}</b></div></div>

      <section className="metric-row">
        <article className={`metric-card verdict ${execution && !blocked ? 'allowed' : ''}`}><small>FINAL VERDICT</small><div><Icon name={execution && !blocked ? 'check' : 'alert'} /><strong>{verdict}</strong></div><p>{blocked ? '실행 차단 · Execution prevented' : execution ? '실행 허용 · Executed in Gateway' : '최종 결정 전 · No execution decision'}</p></article>
        <article className="metric-card"><small>HIGHEST SEVERITY</small><strong>{severity}</strong><p>스캔 {release?.scanStatus ?? '—'} · {release?.status ?? '—'}</p><div className="metric-bar"><b style={{ width: `${report.severityLevel * 25}%` }} /></div></article>
        <article className="metric-card"><small>DETECTED ISSUES</small><strong>{findings.length} <i>Findings</i></strong><p>{major > 0 && <span className="red-dot" />} 주요 위험 {major}건</p></article>
        <article className="metric-card"><small>VALIDATOR CONSENSUS</small><strong>{failVotes || votes.length} <i>/ 3</i></strong><p>{failVotes ? '실행 차단 권고' : votes.length ? '실행 승인' : '판정 대기'}</p><div className="mini-validators">{[0, 1, 2].map((index) => <i key={index} className={votes[index] ? (votes[index].decision === 'FAIL' ? 'fail' : 'pass') : 'none'} />)}</div></article>
      </section>

      <section className="analysis-grid">
        <article className="analysis-map panel">
          <div className="report-panel-head"><div><small>ANALYSIS FLOW</small><h2>Security investigation map</h2></div><span>{seconds ? `Completed in ${seconds}s` : 'In progress'}</span></div>
          <div className="flow-canvas">
            <div className="flow-line" />
            {flow.map(([title, detail, status], index) => <div className={`flow-node ${status}`} key={title}>
              <span className="node-number">0{index + 1}</span>
              <div className="node-core">{status === 'danger' || status === 'blocked' ? <Icon name="alert" /> : status ? <Icon name="check" /> : null}</div>
              <b>{title}</b><small>{detail}</small>
              {status === 'danger' && <em>{report.byStage('SANDBOX')[0]?.code}</em>}
            </div>)}
            <div className={`signal-card signal-one ${behavior ? '' : 'none'}`}><small>BEHAVIOR SIGNAL</small><b>{behavior?.code ?? 'No anomalous behavior'}</b><span>{behavior ? stageName(behavior.stage) : 'All checks passed'}</span></div>
            <div className={`signal-card signal-two ${blocked || !execution ? '' : 'none'}`}><small>POLICY ENGINE</small><b>{execution?.reasonCode ?? (execution ? 'RELEASE_VERIFIED' : 'PENDING')}</b><span>Enforcement: {blocked ? 'block' : execution ? 'allow' : 'pending'}</span></div>
          </div>
          <div className="map-legend"><span><i className="ok" /> Verified</span><span><i className="warn" /> Review</span><span><i className="bad" /> Risk detected</span><b>{short(sessionId)} · {report.releaseId}</b></div>
        </article>

        <aside className="investigation-detail panel">
          <div className="report-panel-head"><div><small>SCAN SUBJECT</small><h2>Result details</h2></div></div>
          <div className="tool-identity"><span>M</span><div><b>mail-mcp</b><small>Version {target}</small></div><em className={report.severityLevel ? '' : 'none'}>{report.severityLevel ? `${severity} RISK` : 'NO FINDINGS'}</em></div>
          <dl><div><dt>Scan ID</dt><dd>{sessionId}</dd></div><div><dt>Repository</dt><dd>demo/fixtures/mail-mcp-{target}</dd></div><div><dt>Severity</dt><dd className={report.severityLevel >= 3 ? 'danger-text' : ''}>{severity} · {findings.length} findings</dd></div><div><dt>Validator notes</dt><dd>{votes.length ? `${failVotes || votes.length} of 3 validators marked this release as ${failVotes ? 'unsafe' : 'safe'} (${votes.map((vote) => vote.validator.replace('Demo Validator ', '')).join(', ')}) → ${release?.status}.` : 'No validator signatures yet.'}</dd></div></dl>
          <div className={`reason-card ${top ? '' : 'none'}`}><small>PRIMARY REASON</small><p>{top?.message ?? '탐지된 보안 문제가 없습니다.'}</p><span>{top ? `Detected during ${stageName(top.stage)}` : 'All analysis stages passed'}</span></div>
          <div className={`final-decision ${execution && !blocked ? 'allowed' : ''}`}><small>EXECUTION DECISION</small><div><span><Icon name={execution && !blocked ? 'check' : 'alert'} /></span><strong>{verdict}</strong></div><p>{blocked ? `Gateway rejected the release before spawn (${execution?.reasonCode}).` : execution ? 'Gateway executed the verified release.' : record.error ?? 'Waiting for the execution decision.'}</p></div>
        </aside>
      </section>

      <section className="lower-results">
        <article className="findings-panel panel">
          <div className="report-panel-head"><div><small>DETECTED ISSUES</small><h2>Findings</h2></div><button>{findings.length} total <span>↗</span></button></div>
          <div className="finding-list">{findings.length ? findings.map((finding, index) => <div className="finding" key={`${finding.code}-${finding.stage}-${index}`}><span className={`severity ${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><b>{finding.code}</b><p>{finding.message}</p></div><small>{stageName(finding.stage)}</small><button aria-label={`Open finding ${index + 1}`}><Icon name="chevron" /></button></div>) : <div className="finding"><span className="severity low">NONE</span><div><b>No findings</b><p>Static · AI · Sandbox 검사에서 탐지된 문제가 없습니다.</p></div></div>}</div>
        </article>
        <article className="evidence-panel panel" id="evidence">
          <div className="report-panel-head"><div><small>TRACE EVIDENCE</small><h2>Evidence & logs</h2></div><span>{timezone()}</span></div>
          <div className="log-list">{session.events.map(({ at, type, detail }, index) => {
            const [level, rowClass, spanClass] = logLevel(type, detail)
            return <div className={rowClass} key={`${at}-${index}`}><time>{clock(at)}</time><span className={spanClass}>{level}</span><p>{detail} <b>{type}</b></p></div>
          })}</div>
          <a className="view-raw" href={`/api/judge/sessions/${sessionId}`} target="_blank" rel="noreferrer">View raw validation logs <span>↗</span></a>
        </article>
      </section>
    </div>
  </>
}

export function ScanResults({ sessionId }: { sessionId: string | null }) {
  const [record, setRecord] = useState<ScanRecord | null | undefined>(undefined)
  useEffect(() => {
    const local = sessionId ? findRecord(sessionId) : loadHistory().find((item) => item.status === 'ALLOWED' || item.status === 'BLOCKED')
    if (local || !sessionId) { setRecord(local ?? null); return }
    getSession(sessionId).then((session) => setRecord(recordFromSession(session)), () => setRecord(null))
  }, [sessionId])

  if (record) return <Shell><Report record={record} /></Shell>
  return <Shell>
    <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Scan Results</div><LanguageSwitcher /></header>
    <div className="ws-content results-content">
      <div className="ws-heading"><div><p>INVESTIGATION REPORT</p><h1>검사 결과</h1><span>보안 검사 결과를 확인합니다.</span></div></div>
      <section className="recent panel"><div className="scan-table"><div className="history-empty">
        <strong>{record === undefined ? '검사 결과를 불러오는 중입니다.' : '표시할 검사 결과가 없습니다.'}</strong>
        <p>보안 검사를 완료하면 이곳에서 결과를 확인할 수 있습니다.</p>
        {record === null && <Link className="ws-button primary" href="/security-scan">보안 검사 시작</Link>}
      </div></div></section>
    </div>
  </Shell>
}
