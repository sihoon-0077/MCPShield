'use client'

import { useState } from 'react'
import { LanguageSwitcher, useLanguage } from './i18n'
import { localize } from './backend-text'
import { Icon, Sidebar } from './workspace'
import { mockSnapshot, unavailableSnapshot } from '../../lib/demo-data'
import type { Snapshot, Source } from '../../lib/types'

const short = (value: string) => `${value.slice(0, 12)}…${value.slice(-6)}`
const chainTone = (status: string) => status === 'REVOKED' ? 'critical' : status === 'VERIFIED' ? 'low' : 'medium'
const pipelineTone = (status: string) => status === 'FAILED' ? 'critical' : status === 'FLAGGED' ? 'medium' : 'low'
const eventLevel = (level: string): [string, string] => level === 'CRITICAL' ? ['log-danger', ''] : level === 'HIGH' || level === 'MEDIUM' ? ['', 'log-warn'] : ['', 'log-info']

// Same MOCK / LIVE / REPLAY source rules as the original Control Room: LIVE falls back to an explicitly labeled REPLAY.
export function Overview() {
  const language = useLanguage()
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot)
  const [loading, setLoading] = useState(false)
  const [notice, setNotice] = useState('Mock mode uses deterministic, local demo data.')
  const [error, setError] = useState<string | null>(null)

  async function selectSource(source: Source) {
    setError(null)
    if (source === 'MOCK') {
      setSnapshot(mockSnapshot)
      setNotice('Mock mode uses deterministic, local demo data.')
      return
    }
    setLoading(true)
    try {
      const response = await fetch(source === 'LIVE' ? '/api/live' : '/api/replay', { cache: 'no-store' })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      setSnapshot(await response.json() as Snapshot)
      setNotice(source === 'LIVE' ? 'Live mode is connected to the Backend API.' : 'Replay mode is showing the saved offline evidence bundle.')
    } catch (cause) {
      if (source === 'LIVE') {
        const message = `Live API unavailable (${cause instanceof Error ? cause.message : 'unknown error'})`
        try {
          const replay = await fetch('/api/replay', { cache: 'no-store' })
          if (!replay.ok) throw new Error(`HTTP ${replay.status}`)
          setSnapshot(await replay.json())
          setError(message)
          setNotice(`${message}; switched explicitly to REPLAY.`)
        } catch (replayError) {
          const combined = `${message}; Replay unavailable (${replayError instanceof Error ? replayError.message : 'unknown error'}). Stale evidence was cleared.`
          setSnapshot(unavailableSnapshot('LIVE'))
          setError(combined)
          setNotice(combined)
        }
      } else {
        const message = `Replay failed: ${cause instanceof Error ? cause.message : 'unknown error'}`
        setSnapshot(unavailableSnapshot('REPLAY'))
        setError(message)
        setNotice(message)
      }
    } finally {
      setLoading(false)
    }
  }

  const malicious = snapshot.releases.find((release) => release.releaseId.endsWith('1.0.1'))
  const baseline = snapshot.releases.find((release) => release.releaseId.endsWith('1.0.0'))
  const failVotes = snapshot.validators.filter((validator) => validator.decision === 'FAIL').length
  const blocks = snapshot.admissions.filter((item) => item.decision === 'BLOCK').length
  const explorer = snapshot.explorerBaseUrl?.replace(/\/$/, '')
  const hasLiveGatewayProof = snapshot.admissions.length > 0 && snapshot.admissions.every((item) => item.source === 'LIVE' && item.spawnAttempted === false)
  const admissionMetric = hasLiveGatewayProof ? ['GATEWAY ENFORCEMENT', 'before process spawn'] : snapshot.source === 'LIVE' ? ['BACKEND ADMISSION', 'no spawn proof'] : ['ADMISSION PREVIEW', 'no live spawn proof']
  const ledger = snapshot.availability === 'UNAVAILABLE' ? 'NO EVIDENCE' : snapshot.ledgerMode === 'LOCAL_DEMO' ? 'LOCAL DEMO LEDGER · NOT ON-CHAIN' : snapshot.ledgerMode ?? (snapshot.source === 'LIVE' ? 'UNKNOWN LEDGER' : 'OFFLINE')
  const explainer = snapshot.availability === 'UNAVAILABLE' ? `No current ${snapshot.source} evidence is loaded; no release, scan, validator, or Gateway claim is shown.` : snapshot.source === 'LIVE' ? 'Fetched now from the Backend API and, when configured, Gateway probe evidence files.' : snapshot.source === 'REPLAY' ? 'Saved offline evidence; no live security claim is implied.' : 'Deterministic product preview; values are synthetic and never presented as live.'
  const revoked = malicious?.chainStatus === 'REVOKED'

  return <div className="workspace results-workspace">
    <Sidebar active="Overview" />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Overview</div><div aria-label="Data source selector" aria-busy={loading}>{(['MOCK', 'LIVE', 'REPLAY'] as Source[]).map((source) => <button key={source} className={`ws-button ${snapshot.source === source ? 'primary' : 'quiet'}`} onClick={() => selectSource(source)} disabled={loading} aria-pressed={snapshot.source === source}>{source}</button>)}<button className="ws-button quiet" onClick={() => selectSource(snapshot.source)} disabled={loading} aria-label={`Refresh ${snapshot.source} data`}><Icon name="refresh" /></button><LanguageSwitcher /></div></header>
      <div className="ws-content results-content">
        <div className="ws-heading"><div><p>RELEASE REGISTRY</p><h1>개요</h1><span role={error ? 'alert' : 'status'} aria-live="polite" className={error ? 'danger-text' : ''}>{notice}</span></div><div className="ws-session"><i /> {loading ? 'LOADING' : snapshot.source} <b>{ledger}</b></div></div>

        <section className="metric-row">
          <article className={`metric-card verdict ${revoked ? '' : malicious?.chainStatus === 'VERIFIED' ? 'allowed' : 'neutral'}`}><small>RELEASE STATUS</small><div><Icon name={revoked ? 'alert' : 'check'} /><strong>{malicious?.chainStatus ?? 'UNAVAILABLE'}</strong></div><p>mail-mcp@1.0.1</p></article>
          <article className="metric-card"><small>VALIDATOR QUORUM</small><strong>{failVotes} <i>/ 3</i></strong><p>{failVotes >= 2 ? 'Threshold reached' : 'Awaiting votes'}</p><div className="mini-validators">{[0, 1, 2].map((index) => <i key={index} className={snapshot.validators[index]?.decision === 'FAIL' ? 'fail' : snapshot.validators[index]?.decision === 'PASS' ? 'pass' : 'none'} />)}</div></article>
          <article className="metric-card"><small>{admissionMetric[0]}</small><strong>{blocks} <i>BLOCK</i></strong><p>{admissionMetric[1]}</p></article>
          <article className="metric-card"><small>EVIDENCE SOURCE</small><strong>{snapshot.availability ?? snapshot.source}</strong><p>{explainer}</p></article>
        </section>

        <section className="lower-results">
          <article className="findings-panel panel">
            <div className="report-panel-head"><div><small>RELEASE COMPARE</small><h2>Baseline vs candidate</h2></div><span>Signed artifacts can still change behavior.</span></div>
            <div className="finding-list" data-raw>
              {snapshot.releases.map((release, index) => <div className="finding" key={release.releaseId}><span className={`severity ${chainTone(release.chainStatus)}`}>{release.chainStatus}</span><div><b>{index === 0 ? 'BASELINE' : 'CANDIDATE'} · {release.releaseId}</b><p>Artifact <span title={release.artifactDigest}>{short(release.artifactDigest)}</span> · Tool surface <span title={release.toolSurfaceHash}>{short(release.toolSurfaceHash)}</span></p></div><small>Scan {release.scanStatus} · Signature {release.signature}</small></div>)}
              {snapshot.releases.length === 2 && <div className="finding"><span className="severity medium">DRIFT</span><div><b>Release identity changes</b><p>Artifact digest {baseline?.artifactDigest !== malicious?.artifactDigest ? 'changed' : 'unchanged'} · Tool surface {baseline?.toolSurfaceHash !== malicious?.toolSurfaceHash ? 'changed' : 'unchanged'}</p></div><small>Publisher signature {malicious?.signature ?? 'UNKNOWN'}</small></div>}
              {snapshot.releases.length === 0 && <div className="finding"><span className="severity low">NONE</span><div><b>No current release evidence is available.</b></div></div>}
            </div>
          </article>
          <article className="evidence-panel panel">
            <div className="report-panel-head"><div><small>VALIDATOR / CHAIN</small><h2>2-of-3 quorum</h2></div><span>{snapshot.ledgerMode === 'LOCAL_DEMO' ? 'Local demo ledger' : 'On-chain status'}</span></div>
            <div className="log-list">
              {snapshot.validators.map((validator) => <div key={validator.id}><time>{validator.id}</time><span className={validator.decision === 'FAIL' ? 'log-block' : validator.decision === 'PASS' ? 'log-info' : ''}>{validator.decision}</span><p>{validator.txHash ? <b title={validator.txHash}>{short(validator.txHash)}</b> : 'No transaction'}</p></div>)}
              {snapshot.validators.length === 0 && <div><time>—</time><span /><p>No validator votes are available from this source.</p></div>}
              <div className={revoked ? 'log-danger' : ''}><time>mail-mcp@1.0.1</time><span>{malicious?.chainStatus ?? 'N/A'}</span><p>{malicious?.txHash && explorer ? <a href={`${explorer}/tx/${encodeURIComponent(malicious.txHash)}`} target="_blank" rel="noreferrer">View transaction ↗</a> : malicious?.txHash ? <b title={malicious.txHash}>{short(malicious.txHash)}</b> : 'No status transaction'}</p></div>
            </div>
          </article>
        </section>

        <section className="lower-results">
          <article className="findings-panel panel">
            <div className="report-panel-head"><div><small>SCAN PIPELINE</small><h2>Static · AI · Sandbox</h2></div></div>
            <div className="finding-list" data-raw>
              {snapshot.pipeline.map((item) => <div className="finding" key={item.stage}><span className={`severity ${pipelineTone(item.status)}`}>{item.status}</span><div><b>{item.stage}</b><p>{localize(item.detail, language)}</p></div></div>)}
              {snapshot.pipeline.length === 0 && <div className="finding"><span className="severity low">NONE</span><div><b>No scan pipeline evidence is available.</b></div></div>}
            </div>
          </article>
          <article className="evidence-panel panel">
            <div className="report-panel-head"><div><small>SANDBOX TIMELINE</small><h2>Runtime events</h2></div><span>{snapshot.sandboxEvents.length} events</span></div>
            <div className="log-list">
              {snapshot.sandboxEvents.map((event) => { const [row, span] = eventLevel(event.level); return <div className={row} key={`${event.time}-${event.type}`}><time>{event.time}</time><span className={span}>{event.level}</span><p>{localize(event.detail, language)} <b>{event.type}</b></p></div> })}
              {snapshot.sandboxEvents.length === 0 && <div><time>—</time><span /><p>No sandbox events are available from this source.</p></div>}
            </div>
          </article>
        </section>

        <section className="recent panel">
          <div className="recent-head"><div><h2>Agent admission</h2><p>Gateway decisions for the exact release identity</p></div></div>
          <div className="scan-table">
            <div className="table-row table-labels"><span>GATEWAY</span><span>RELEASE</span><span>DECISION</span><span>REASON</span><span>CHECKED</span><span /></div>
            {snapshot.admissions.map((item, index) => <div className="table-row" key={`${item.gateway}-${item.releaseId}-${index}`}><span className="tool-name"><i>{item.gateway.replace(/^Gateway /, '').slice(0, 1)}</i><b>{item.gateway}</b></span><span className="mono">{item.releaseId}</span><span><b className={`status ${item.decision === 'BLOCK' ? 'blocked' : 'allowed'}`}>{item.decision}</b></span><span className={`risk ${item.decision === 'BLOCK' ? 'high' : 'low'}`}>{item.reasonCode.replaceAll('_', ' ')}{item.spawnAttempted === false ? ' · PRE-SPAWN' : ''}</span><span>{item.checkedAt ? new Date(item.checkedAt).toLocaleTimeString('en-GB') : '—'}</span><span /></div>)}
            {snapshot.admissions.length === 0 && <div className="history-empty"><strong>No current Gateway admission decisions are available.</strong></div>}
          </div>
        </section>
        <p className="overview-footnote">Evidence-first MCP supply chain security · generated <time dateTime={snapshot.generatedAt}>{snapshot.generatedAt}</time></p>
      </div>
    </main>
  </div>
}
