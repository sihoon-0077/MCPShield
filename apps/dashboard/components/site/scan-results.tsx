'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { AdmissionView, VotesV3View, outcomeName } from '../release-workflow'
import { LanguageSwitcher } from './i18n'
import { Icon, Sidebar } from './workspace'
import { useLatestScan, useSession, useV3Run } from './v3-api'
import { chainLabel, clock, short, when } from './v3-model'
import { FindingsPanel, LoginRequired, V3FlowMap, VerdictCards } from './v3-views'

function Shell({ children }: { children: React.ReactNode }) {
  return <div className="workspace results-workspace">
    <Sidebar active="Scan Results" />
    <main className="ws-main">{children}</main>
  </div>
}

function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return <>
    <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> 검사 결과</div><LanguageSwitcher /></header>
    <div className="ws-content results-content">
      <div className="ws-heading"><div><p>INVESTIGATION REPORT</p><h1>검사 결과</h1><span>검증자 A·B·C의 표와 체인 결론, 실행 판정 조회 결과입니다.</span></div></div>
      <section className="recent panel"><div className="scan-table"><div className="history-empty" data-raw><strong>{title}</strong>{children}</div></div></section>
    </div>
  </>
}

function Report({ scanId, releaseId }: { scanId: string | null; releaseId: string | null }) {
  const run = useV3Run({ scanId, releaseId }, { poll: false })
  const { release, scan, votes, round, flow, admission } = run
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer) }, [])
  const ready = Boolean(votes && release)
  useEffect(() => {
    if (ready && window.location.hash === '#evidence') document.getElementById('evidence')?.scrollIntoView()
  }, [ready])

  if (run.session.status === 'signed-out' || run.signedOut) return <Empty title="운영자 로그인이 필요합니다."><LoginRequired /></Empty>
  if (run.notFound) return <Empty title="표시할 검사 결과가 없습니다."><p>{run.error}</p><Link className="ws-button primary" href="/security-scan">보안 검사 시작</Link></Empty>
  if (!ready) return <Empty title={run.error || '검사 결과를 불러오는 중입니다.'}>{run.error && <button className="ws-button quiet" onClick={run.refresh}>다시 조회</button>}</Empty>

  const version = release!.version
  const decided = Boolean(round && round.outcome !== 'OPEN')
  const revoked = votes!.status === 'REVOKED'
  const scanResult = scan?.result as (NonNullable<typeof scan>['result'] & { validFrom?: string }) | undefined
  const policyHash = scan?.policyHash ?? votes!.policyHash
  const policy = run.policies.find((item) => item.policyHash === policyHash)
  const exportReport = () => {
    const body = { exportedAt: new Date().toISOString(), source: 'MCPShield V3 운영 API', chain: { chainId: flow.chainId, label: chainLabel(flow.chainId) }, release, scan, round: round ?? null, votes, admission }
    const url = URL.createObjectURL(new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url; link.download = `mcpshield-v3-${release!.legacyReleaseId.replace(/[^a-z0-9.@-]/gi, '_')}-${(round?.roundId ?? 'no-round').slice(2, 10)}.json`; link.click()
    URL.revokeObjectURL(url)
  }

  return <>
    <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> 검사 결과</div><div>
      <button className="ws-button quiet" onClick={exportReport}><Icon name="download" /> 보고서 내보내기 (JSON)</button>
      {!revoked && <Link className="ws-button quiet" href={`/security-scan?version=${version}`}><Icon name="refresh" /> 다시 검사</Link>}
      <a className="ws-button quiet" href={`/api/control/releases/${release!.releaseId}/votes${policyHash ? `?policyHash=${policyHash}` : ''}`} target="_blank" rel="noreferrer">원본 투표 JSON ↗</a>
      <LanguageSwitcher /></div></header>
    <div className="ws-content results-content">
      <div className="ws-heading"><div><p>INVESTIGATION REPORT</p><h1>검사 결과</h1><span data-raw>{release!.legacyReleaseId} · {chainLabel(flow.chainId)} · 라운드 {short(round?.roundId)}</span></div>
        <div className="ws-session" data-raw><i className={round?.outcome === 'APPROVED' ? '' : round?.outcome === 'REJECTED' ? 'fail' : 'review'} /> <b>{round ? outcomeName[round.outcome] ?? round.outcome : '라운드 없음'}</b></div></div>
      {run.error && <p className="v3-banner fail" role="alert" data-raw>조회 실패 · 아래는 마지막 성공 {clock(run.at)} 기준입니다. {run.error} <button className="ws-button quiet" onClick={run.refresh}>다시 조회</button></p>}
      {!decided && <p className="v3-banner" data-raw>{round ? '아직 결론이 나지 않았습니다.' : '이 검사의 투표 라운드가 아직 없습니다.'} {scan && <Link href={`/scan-progress?scan=${scan.scanId}`}>진행 화면 보기 ↗</Link>}</p>}

      <VerdictCards votes={votes} release={release} admission={admission} round={round} loading={run.loading} />

      <section className="analysis-map panel v3-map-panel">
        <div className="report-panel-head"><div><small>ANALYSIS FLOW</small><h2>검증 흐름</h2></div><span>운영사 → 검증자 A·B·C → 2-of-3 → Gateway</span></div>
        <V3FlowMap flow={flow} />
        <div className="map-legend" data-raw><span><i className="ok" /> 통과</span><span><i className="warn" /> 보류</span><span><i className="bad" /> 불합격</span><span><i className="nil" /> 기록 없음</span><b>{short(round?.roundId)} · {release!.legacyReleaseId}</b></div>
      </section>

      <section className="lower-results">
        <aside className="investigation-detail panel" data-raw>
          <div className="report-panel-head"><div><small>SCAN SUBJECT</small><h2>검사 대상</h2></div></div>
          <dl>
            <div><dt>릴리스 ID</dt><dd className="mono">{release!.releaseId}</dd></div>
            <div><dt>아티팩트 digest</dt><dd className="mono">{release!.artifactDigest}</dd></div>
            <div><dt>매니페스트 digest</dt><dd className="mono">{release!.manifestDigest ?? '—'}</dd></div>
            <div><dt>도구 표면 (tool surface)</dt><dd className="mono">{release!.toolSurfaceHash}</dd></div>
            <div><dt>정책</dt><dd>{policy?.alias ?? '정책 이름 확인 불가'} · <code>{short(policyHash)}</code></dd></div>
            <div><dt>체인</dt><dd>{chainLabel(flow.chainId)} · 레지스트리 <code>{short(release!.chain?.registryContract ?? run.actions[0]?.registryAddress)}</code></dd></div>
            <div><dt>유효기간</dt><dd>{round ? `${when(round.validFrom)} ~ ${when(round.validUntil)}` : '—'}</dd></div>
            <div><dt>운영사 참고 검사</dt><dd>{scan ? `${scanResult?.verdict ?? '—'} · ${scanResult?.state ?? scan.status} · 분석 ${scanResult?.scanResult?.scanStatus ?? '—'} · 판정에 반영되지 않음` : '운영사 검사 기록 없음 (다른 경로로 열린 라운드)'}</dd></div>
          </dl>
          <div className={`final-decision ${admission?.decision === 'ALLOW' ? 'allowed' : ''}`} data-gateway={admission?.decision ?? 'NONE'}><small>실행 판정 (API 조회)</small>
            <div><span><Icon name={admission?.decision === 'ALLOW' ? 'check' : 'alert'} /></span><strong>{admission?.decision ?? (decided ? '조회 중' : '결론 후 조회')}</strong></div>
            <p>{admission ? `${admission.reasonCode} · 조회 ${when(admission.checkedAt)}` : '라운드 결론 뒤 API에 조회합니다.'}</p>
            <p>실제 Gateway가 실행 직전에 판정을 다시 조회하고 VERIFIED일 때만 실행합니다. 이 화면은 도구를 실행하지 않습니다.</p></div>
        </aside>
        <article className="findings-panel panel">
          <div className="report-panel-head"><div><small>DETECTED ISSUES</small><h2>검증자 증거의 탐지 항목</h2></div><span>운영사 검사 아님</span></div>
          <FindingsPanel round={round} votes={votes} />
        </article>
      </section>

      <section className="evidence-panel panel v3-evidence" id="evidence">
        <div className="report-panel-head"><div><small>TRACE EVIDENCE</small><h2>검증자별 투표 · 체인 기록</h2></div><span>체인에서 읽은 표 · 운영 API가 해시를 대조한 증거 요약</span></div>
        <div className="ops" data-raw>
          <VotesV3View votes={votes} operatorVerdicts={scan ? { [scan.scanId]: scan.result?.verdict } : {}} />
          <AdmissionView admission={admission} now={now} />
        </div>
      </section>
    </div>
  </>
}

// /scan-results?scan=… | ?release=… | (newest completed scan). Malformed values count as missing.
export function ScanResults({ scanId, releaseId }: { scanId: string | null; releaseId: string | null }) {
  const session = useSession()
  const latest = useLatestScan(!scanId && !releaseId && session.status === 'signed-in')
  if (scanId || releaseId) return <Shell><Report scanId={scanId} releaseId={scanId ? null : releaseId} /></Shell>
  if (session.status === 'signed-out' || latest.signedOut) return <Shell><Empty title="운영자 로그인이 필요합니다."><LoginRequired /></Empty></Shell>
  if (session.status === 'error') return <Shell><Empty title={session.message} /></Shell>
  if (latest.scanId) return <Shell><Report scanId={latest.scanId} releaseId={null} /></Shell>
  return <Shell><Empty title={latest.scanId === null ? '표시할 검사 결과가 없습니다.' : '검사 결과를 불러오는 중입니다.'}>
    {latest.scanId === null && <><p>{latest.error || '운영 API에 완료된 검사가 없습니다.'}</p><Link className="ws-button primary" href="/security-scan">보안 검사 시작</Link></>}
  </Empty></Shell>
}
