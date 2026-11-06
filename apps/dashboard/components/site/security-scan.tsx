'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { controlApi } from '../../lib/control-client'
import type { Admission } from '../release-workflow'
import { LanguageSwitcher } from './i18n'
import { Icon, Sidebar } from './workspace'
import { checkAdmission, startScan, useBoard, useSession, type StartPhase } from './v3-api'
import { FIXTURE_VERSIONS, chainIdOf, chainLabel, chainState, consensusCard, decidedOnChain, fixtureRelease, flowView, short, shownRound, when, type FixtureVersion } from './v3-model'
import { LoginRequired, RunsTable, laneDotKind, statusDotKind } from './v3-views'

const buttonText: Record<'idle' | StartPhase, string> = { idle: '보안 검사 시작', resolving: '릴리스 확인 중…', registering: '체인 등록 중…', requesting: '검사 요청 중…' }
// The two reviewed fixtures. 1.0.1 is the malicious update written for the demo (it leaks a dummy canary).
const OPTIONS: Record<FixtureVersion, { tag: string; tone: string; text: string }> = {
  '1.0.0': { tag: '정상 버전', tone: '', text: '메일 목록을 읽는 기준 버전입니다.' },
  '1.0.1': { tag: '악성 업데이트', tone: 'risky', text: '시연용으로 만든 위험한 업데이트입니다. 데이터를 몰래 내보내는 코드가 들어 있습니다.' },
}

// The operator registers the exact release and announces a round; validators A, B and C decide it on chain.
export function SecurityScan({ initialVersion }: { initialVersion: FixtureVersion }) {
  const router = useRouter()
  const session = useSession()
  const signedIn = session.status === 'signed-in'
  const checking = session.status === 'loading'
  const { board, error: boardError } = useBoard(signedIn)
  const [version, setVersion] = useState<FixtureVersion>(initialVersion)
  const [phase, setPhase] = useState<'idle' | StartPhase>('idle')
  const [error, setError] = useState('')
  const [admission, setAdmission] = useState<Admission | null>(null)

  const stateOf = (target: FixtureVersion) => {
    const item = fixtureRelease(board?.releases, target)
    return { release: item, state: chainState({ votes: item ? board?.votes[item.releaseId] : undefined, release: item, error: item ? board?.voteErrors[item.releaseId] ?? null : null }) }
  }
  const stateText = (target: FixtureVersion) => { const { release: item, state: chain } = stateOf(target); return !signedIn ? (checking ? '세션 확인 중' : '로그인 후 표시') : !board ? '불러오는 중' : !item ? '아직 검사 안 함' : chain.text }

  const release = fixtureRelease(board?.releases, version)
  const votes = release ? board?.votes[release.releaseId] : undefined
  const votesError = release ? board?.voteErrors[release.releaseId] ?? null : null
  const round = shownRound(votes)
  const state = chainState({ votes, release, error: votesError })
  const status = state.status
  const revoked = status === 'REVOKED'
  const split = Boolean(votes?.needsReview) || round?.outcome === 'SPLIT'
  const live = votes?.rounds.find((item) => item.live)
  const scan = board?.scans.find((item) => item.scanId === round?.scanId)
  const flow = flowView({ release, scan, votes, round, actions: board?.actions, admission, votesError })
  const chainId = chainIdOf({ release, actions: board?.actions, admission })
  const capabilities = signedIn ? session.session.capabilities : null
  const reader = signedIn && !capabilities?.scan
  const busy = phase !== 'idle'
  const decided = decidedOnChain(status, round)
  const policyHash = votes?.policyHash

  // Only a release the chain has a conclusion for is looked up: every lookup is written to the audit log like a Gateway check.
  useEffect(() => {
    setAdmission(null)
    if (!release || !policyHash || !decided) return
    const controller = new AbortController()
    checkAdmission(release, policyHash, controller.signal).then(setAdmission, () => {})
    return () => controller.abort()
  }, [release, policyHash, decided])

  const start = async () => {
    if (revoked && release) { router.push(`/scan-results?release=${release.releaseId}`); return }
    if (!capabilities || !board) return
    setError('')
    try {
      const result = await startScan(version, { api: controlApi, capabilities, policies: board.policies, attemptKey: crypto.randomUUID(), onPhase: setPhase })
      router.push(result.kind === 'revoked' ? `/scan-results?release=${result.releaseId}` : `/scan-progress?scan=${result.scanId}${result.reused ? '&reused=1' : ''}`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '검사를 시작하지 못했습니다.')
      setPhase('idle')
    }
  }

  const kind = statusDotKind(status)
  const detail = status === 'VERIFIED' && live ? ` · ${when(live.validUntil)}까지 유효` : split && status === 'UNVERIFIED' ? ' · 표가 갈림 · 사람 검토 전까지 실행 차단' : ''
  return <div className="workspace">
    <Sidebar active="Security Scan" />

    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> 보안 검사</div><div><LanguageSwitcher /></div></header>
      <div className="ws-content">
        <div className="ws-heading"><div><p>SECURITY WORKSPACE</p><h1>보안 검사</h1><span>검사할 버전을 고르고 시작하면, 검증자 A·B·C가 각자 검사해 승인 또는 폐기를 결정합니다.</span></div>
          <div className="ws-session" data-raw><i className={signedIn ? '' : 'off'} /> {signedIn ? <>운영 API · <b>{session.session.tenantId} · {session.session.role}</b></> : checking ? '세션 확인 중' : '로그인 필요'}</div></div>
        {session.status === 'error' && <p className="scan-error v3-banner" role="alert">{session.message}</p>}
        {boardError && <p className="scan-error v3-banner" role="alert">{boardError}</p>}
        {votesError && <p className="scan-error v3-banner" role="alert" data-raw>이 버전의 체인 투표를 읽지 못했습니다 · 상태 미확인 (승인으로 간주하지 않음). {votesError}</p>}

        <section className="pick-layout">
          <div className="panel pick-panel">
            <div className="pick-head"><h2>어떤 업데이트를 검사할까요?</h2><p>시연용으로 준비한 mail-mcp의 두 버전 중 하나를 고르세요.</p></div>
            <div className="pick-cards" role="radiogroup" aria-label="검사할 버전">{FIXTURE_VERSIONS.map((target) => { const option = OPTIONS[target], chain = stateOf(target).state
              return <button type="button" role="radio" aria-checked={version === target} key={target} className={`pick-card ${option.tone} ${version === target ? 'selected' : ''}`} data-version={target}
                onClick={() => { setVersion(target); setError('') }} disabled={busy} data-raw>
                <span className="pick-tag">{option.tag}</span>
                <b>mail-mcp<code>{target}</code></b>
                <p>{option.text}</p>
                <span className="pick-state"><i className={`fx-dot ${statusDotKind(chain.status)}`} />{stateText(target)}</span>
              </button> })}</div>
            <dl className="pick-facts" data-raw>
              <div><dt>파일 지문 (자동 계산)</dt><dd title={release?.artifactDigest ?? ''}>{release?.artifactDigest ? short(release.artifactDigest) : '검사를 시작하면 고정됩니다'}</dd></div>
              <div><dt>검사 정책</dt><dd>{board ? `${board.defaultPolicy?.alias ?? '기본 정책 없음'} · 2-of-3` : '—'}</dd></div>
              <div><dt>체인</dt><dd>{signedIn ? chainLabel(chainId) : checking ? '세션 확인 중' : '로그인 후 표시'}</dd></div>
            </dl>
            {error && <p className="scan-error" role="alert" data-raw>{error}</p>}
            {reader && <p className="scan-error" role="status">검사 요청은 운영자 이상 권한이 필요합니다 (현재 {session.status === 'signed-in' ? session.session.role : 'reader'}).</p>}
            {session.status === 'signed-out' ? <div className="form-actions v3-login-slot"><LoginRequired /></div> : <div className="pick-actions">
              <p data-raw>{revoked ? '폐기는 영구입니다. 같은 바이트는 다시 등록·승인할 수 없어 새 검사를 열지 않습니다.' : '같은 버전·정책의 PASS/FAIL 검사가 24시간 안에 있으면 그 결과를 다시 보여 줍니다 (새 라운드 없음).'}</p>
              <button className="ws-button primary scan-start" onClick={() => void start()} disabled={!signedIn || !board || busy || (reader && !revoked)}><Icon name={revoked ? 'result' : 'scan'} /> {revoked ? '폐기 근거 보기' : buttonText[phase]}</button>
            </div>}
          </div>

          <aside className="panel pick-side" data-raw>
            <div className="pick-side-head"><small>선택한 버전의 현재 상태</small><h3 className={kind}><i className={`fx-dot ${kind}`} />{stateText(version)}</h3><span>mail-mcp@{version}{detail}</span></div>
            {signedIn && board && <>
              <div className="ov-row"><span>검증자</span><span className="ov-lanes">{flow.lanes.map((lane) => <span key={lane.lane}><b>{lane.lane}</b><i className={`fx-dot ${laneDotKind(lane)}`} /></span>)}</span><em>{consensusCard(round).value}</em></div>
              <div className="ov-row" data-gateway={admission?.decision ?? 'NONE'}><span>실행 판정</span>{admission ? <b className={`fx-chip ${admission.decision === 'ALLOW' ? 'pass' : 'fail'}`}>{admission.decision}</b> : <b className="fx-chip">{decided ? '조회 중' : '조회 안 함'}</b>}<em>{admission?.reasonCode ?? ''}</em></div>
              <p className="pick-note">{admission ? '실제 Gateway가 실행 직전에 판정을 다시 확인합니다. 이 화면은 도구를 실행하지 않습니다.' : decided ? '체인 결론으로 API에 실행 판정을 조회하고 있습니다.' : '체인 결론이 아직 없어 실행 판정을 조회하지 않았습니다 (실행 차단).'}</p>
              {release && <a className="result-link" href={`/scan-results?release=${release.releaseId}`}>전체 결과 보기 <span>↗</span></a>}
            </>}
          </aside>
        </section>

        <section className="recent panel">
          <div className="recent-head"><div><h2>최근 검사</h2><p>운영 API에 저장된 이 조직의 최근 검사</p></div><a className="v3-link" href="/history">전체 기록 보기 <span>↗</span></a></div>
          {!signedIn ? <div className="scan-table"><div className="history-empty"><strong>{checking ? '운영 API 세션을 확인하고 있습니다.' : '로그인 후 체인 기록을 불러옵니다.'}</strong></div></div>
            : board?.scans.length ? <RunsTable board={board} limit={4} />
            : <div className="scan-table"><div className="history-empty"><strong>{board ? '아직 검사 기록이 없습니다.' : '검사 기록을 불러오는 중입니다.'}</strong></div></div>}
        </section>
      </div>
    </main>
  </div>
}
