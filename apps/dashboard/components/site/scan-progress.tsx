'use client'

import Link from 'next/link'
import { LanguageSwitcher } from './i18n'
import { Icon, Sidebar } from './workspace'
import { useV3Run } from './v3-api'
import { chainLabel, clock, laneOf, statusKo, toolName, when, type Phase } from './v3-model'
import { EventsList, LoginRequired, V3FlowMap, shownEvents } from './v3-views'

const phaseLabel: Record<Phase, string> = { none: '—', login: '로그인 필요', loading: '불러오는 중', operator: '운영사 검사', validators: '검증자 투표', decided: '결론 기록',
  done: '완료', terminal: '폐기됨', stalled: '응답 없음', missing: '기록 없음', error: '실패' }
const phaseTone: Partial<Record<Phase, string>> = { operator: 'scanning', validators: 'scanning', decided: 'waiting', done: 'completed', terminal: 'failed', stalled: 'waiting', missing: 'waiting', error: 'failed' }

// One operator scan followed live from the V3 operator API: its round, each validator's own vote, the 2-of-3 result and the admission lookup.
export function ScanProgress({ scanId, reused }: { scanId: string | null; reused: boolean }) {
  const run = useV3Run({ scanId }, { poll: true })
  const { phase, flow, scan, release, votes, round, admission } = run
  const finished = phase === 'done' || phase === 'terminal'
  const status = votes?.status
  const quarantine = status === 'QUARANTINED' ? votes?.quarantines?.find((item) => item.expiresAt === votes.quarantineUntil) ?? votes?.quarantines?.[0] : undefined
  const lastError = (scan?.lastError ?? null) as { code?: string } | null
  const split = round?.outcome === 'SPLIT' || Boolean(votes?.needsReview)
  const decidedTitle = round?.outcome === 'APPROVED' ? '2/3 PASS · 승인이 체인에 기록되었습니다.' : round?.outcome === 'REJECTED' ? '2/3 FAIL · 폐기가 체인에 기록되었습니다.' : '표가 갈렸습니다 · 사람 검토가 필요합니다.'
  const gatewayLine = `Gateway 실행 판정 ${admission?.decision ?? '—'} (${admission?.reasonCode ?? '—'}). 실제 Gateway가 실행 직전에 판정을 다시 조회하고 VERIFIED일 때만 실행합니다.`
  const doneTitle = split && status !== 'REVOKED' ? '이번 라운드가 끝났습니다 · 표가 갈림' : `이번 라운드가 끝났습니다 · ${statusKo(status)}`
  const doneText = status === 'VERIFIED' ? `승인됨 · ${when(round?.validUntil)}까지 유효하고, 그 뒤에는 다시 검사합니다. ${gatewayLine}`
    : split && status !== 'REVOKED' ? `표가 갈림 · 사람 검토 전까지 실행 차단. ${gatewayLine}`
    : status === 'REVOKED' ? `폐기됨 · 영구 (같은 바이트 재등록 불가). ${gatewayLine}` : gatewayLine
  const [title, description] = {
    none: ['진행 중인 검사가 없습니다.', '보안 검사 화면에서 버전을 고르고 검사를 시작하세요.'],
    login: ['운영자 로그인이 필요합니다.', '검사 기록은 운영 API에서 읽습니다.'],
    loading: ['검사 기록을 불러오는 중입니다.', '운영 API에서 검사와 체인 투표를 읽고 있습니다.'],
    operator: ['운영사가 라운드를 준비하고 있습니다.', '운영사 검사는 이번 라운드의 유효기간(최대 24시간)만 정합니다. 표는 이 안에서만 받고, 승인되면 이 시각까지만 유효합니다. 승인·폐기 판정은 하지 않습니다.'],
    validators: ['검증자 A·B·C가 각자 검사하고 있습니다.', '각 검증자가 자기 사본을 다시 검사하고, 자기 증거 해시와 판정에 직접 서명합니다. 운영사는 서명된 표를 그대로 중계만 합니다.'],
    decided: [decidedTitle, '남은 표도 그대로 기록됩니다. 결론 뒤 표는 결과를 바꾸지 않습니다.'],
    done: [doneTitle, doneText],
    terminal: ['이미 폐기된 릴리스입니다.', '새 라운드의 투표는 체인이 거부합니다(TERMINAL_RELEASE). 폐기를 정한 라운드의 늦은 표는 기록만 됩니다. 폐기 근거를 확인하세요.'],
    stalled: ['검증자 표가 아직 없습니다.', '검증자 프로세스가 실행 중인지 스택 로그를 확인하세요. 표가 없으면 승인으로 간주하지 않습니다.'],
    missing: ['검사 기록을 찾을 수 없습니다.', run.error || '이 조직의 운영 API에 이 검사 ID가 없습니다. 보안 검사 화면에서 새 검사를 시작하세요.'],
    error: ['검사를 완료하지 못했습니다.', run.error || lastError?.code || '운영 API가 검사 기록을 돌려주지 않았습니다.'],
  }[phase]
  const showMap = Boolean(scan) && !['none', 'login', 'loading', 'missing', 'error'].includes(phase)
  const resultHref = phase === 'terminal' ? `/scan-results?release=${release?.releaseId ?? scan?.releaseId ?? ''}` : `/scan-results?scan=${scanId}`
  const resultLink = finished ? <Link className="ws-button primary" href={resultHref}>{phase === 'terminal' ? '폐기 근거 보기' : '검증 결과 보기'} <span>↗</span></Link> : null
  const filter = { since: scan?.createdAt, scanId: scan?.scanId, roundId: round?.roundId }
  const stale = Boolean(run.error) && !['missing', 'error'].includes(phase)

  return <div className="workspace progress-workspace">
    <Sidebar active="Security Scan" className="progress-sidebar" />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> 보안 검사 <b>/</b> 검증 진행</div><div className="ws-topbar-actions"><Link className="ws-button quiet" href="/security-scan"><Icon name="arrow" /> 검사 화면으로 돌아가기</Link>{resultLink}<LanguageSwitcher /></div></header>
      <div className="ws-content progress-content">
        <div className="progress-heading"><div><div className="live-label"><i /> V3 검증 진행 <span>운영 API · 1.5초마다 조회</span></div><h1>{phase === 'done' ? '이번 라운드가 끝났습니다.' : phase === 'terminal' ? '폐기된 릴리스입니다.' : phase === 'missing' ? '검사 기록을 찾을 수 없습니다.' : phase === 'error' ? '검증 기록을 확인할 수 없습니다.' : phase === 'none' ? '진행 중인 검사가 없습니다.' : phase === 'login' ? '운영자 로그인이 필요합니다.' : '검증을 진행하고 있습니다.'}</h1><p>운영사는 등록과 라운드 공지만 합니다. 검증자 A·B·C(팀이 운영하는 역할 이름)가 각자 다시 검사하고 직접 서명한 표를 운영사가 그대로 중계합니다.</p></div>
          <div className="scan-meta" data-raw><span><small>MCP 도구</small><b>{toolName(release)}</b></span><span><small>버전</small><b>{release?.version ?? '—'}</b></span><span><small>검사 ID</small><b>{scanId ? scanId.slice(0, 8) : '—'}</b></span><span><small>상태</small><b className={phaseTone[phase] ?? ''} data-phase={phase}>{phaseLabel[phase]}</b></span></div></div>

        <section className={`pipeline-panel panel ${phase === 'error' ? 'has-failed' : ''}`} data-raw>
          <div className="pipeline-top"><div><small>검증 단계</small><h2>{title}</h2>{phase === 'login' ? null : <p>{description}</p>}</div><div className="stage-count"><b>{flow.done}</b><span>/5 단계 완료</span></div></div>
          <div className="stage-progress"><i style={{ width: `${(flow.done / 5) * 100}%` }} /></div>
          {phase === 'login' && <div className="v3-pad"><LoginRequired /></div>}
          {stale && <p className="v3-banner fail" role="alert">조회 실패 · 아래는 마지막 성공 {run.at ? clock(run.at) : '—'} 기준입니다. 5초마다 다시 조회합니다. {run.error}</p>}
          {quarantine && <p className="v3-banner fail">검증자 {laneOf(votes, quarantine.validator) ?? '확인 중'}가 긴급 격리를 걸었습니다 · {when(votes?.quarantineUntil)}까지 실행 차단. 폐기는 별도로 FAIL 2표가 필요합니다.</p>}
          {reused && <p className="v3-banner">기존 검사 재사용 · 새 라운드 없음: 같은 버전·정책의 PASS/FAIL 검사가 24시간 안에 있어 그 결과를 보여 줍니다.</p>}
          {showMap && <V3FlowMap flow={flow} />}
          <div className="demo-controls"><span>{chainLabel(flow.chainId)} · 표는 블록에 담긴 뒤 체인 기록으로 표시됩니다.</span><div>
            {phase === 'none' || phase === 'missing' ? <Link className="ws-button primary" href="/security-scan">보안 검사로 이동</Link>
              : phase === 'error' ? <><button className="ws-button quiet" onClick={run.refresh}>다시 조회</button><Link className="ws-button primary" href="/security-scan">새 검사 시작</Link></>
              : finished ? resultLink
              : phase === 'login' ? null : <button className="ws-button primary" disabled>검증 진행 중…</button>}
          </div></div>
        </section>

        {showMap && <section className="v3-events-panel panel" data-raw>
          <div className="live-panel-head"><div><small>RELEASE HISTORY</small><h2>릴리스 이력</h2></div><span>{shownEvents(run.history, votes, filter)}건</span></div>
          <EventsList history={run.history} votes={votes} {...filter} />
          <div className="events-note"><i /> 운영 API 릴리스 이력 중 이 검사와 이 라운드의 기록입니다. &lsquo;중계 접수&rsquo;는 아직 체인 기록이 아닙니다.</div>
        </section>}
      </div>
    </main>
  </div>
}
