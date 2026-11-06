'use client'

import React, { useEffect, useRef, useState } from 'react'
import type { Admission } from '../release-workflow'
import { LanguageSwitcher } from './i18n'
import { Sidebar } from './workspace'
import { checkAdmission, useBoard, useSession } from './v3-api'
import { AI_WITNESS_NOTE, TEAM_RUN_NOTE, chainIdOf, chainLabel, chainState, consensusCard, decidedOnChain, flowView, shownRound } from './v3-model'
import { LoginRequired, V3FlowMap, laneDotKind, statusDotKind } from './v3-views'
import { HOW_SCENES } from './how-scenes'

// How MCPShield works, in the order of the team's intro film; each step has a looping scene drawn in how-scenes.tsx.
const HOW: { key: string; no: string; kicker: string; title: string; text: string; wide?: boolean; flip?: boolean }[] = [
  { key: 'fingerprint', no: '01', kicker: 'THE EXACT RELEASE', title: '이름이 아닌, 배포본의 지문.', text: '새 버전의 파일 · 매니페스트 · 도구 목록 해시를 체인에 고정합니다. 이름이 같아도 바이트가 다르면 다른 릴리스입니다.' },
  { key: 'layers', no: '02', kicker: 'INSIDE EACH VALIDATOR', title: 'AI를 더한, 세 겹의 검증.', text: '코드 규칙 검사 · 의미 분석 · Sandbox 실행으로 증거를 교차 확인합니다. AI는 증인으로만 참여하고, 의심되면 통과를 보류할 뿐입니다.', wide: true },
  { key: 'validators', no: '03', kicker: 'INDEPENDENT EVIDENCE', title: '각자의 검사. 각자의 서명.', text: '검증자 A · B · C가 각자 자기 사본을 검사하고, 자기 증거와 판정에 직접 서명합니다.', flip: true },
  { key: 'quorum', no: '04', kicker: 'TWO OF THREE', title: '세 곳 중 두 곳. 함께 쓰는 하나의 판정.', text: '두 곳 이상이 같은 판정을 내면 스마트 컨트랙트에 승인 또는 폐기가 기록됩니다. 반대표도 지워지지 않습니다.', wide: true },
  { key: 'gateway', no: '05', kicker: 'CHECK BEFORE EXECUTION', title: '확인은, 실행 직전에.', text: 'Gateway가 도구를 실행하기 직전에 해시와 체인 판정을 다시 확인하고, 승인된 배포본만 실행합니다.' },
  { key: 'blocked', no: '06', kicker: 'REVOKED → BLOCKED', title: '위험한 업데이트는, 실행 전에 멈춘다.', text: '폐기되거나 격리된 버전은 프로세스를 띄우기 전에 차단됩니다. 이전 버전의 승인은 이어지지 않습니다.', flip: true },
]

// Each step fades in as it scrolls into view. Without JavaScript (and before mount) every step is simply visible.
function useReveal() {
  const ref = useRef<HTMLOListElement>(null)
  useEffect(() => {
    const root = ref.current
    if (!root) return
    root.dataset.reveal = 'on'
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) if (entry.isIntersecting) { entry.target.classList.add('in'); observer.unobserve(entry.target) }
    }, { threshold: 0.3 })
    root.querySelectorAll('.how-step').forEach((step) => observer.observe(step))
    return () => observer.disconnect()
  }, [])
  return ref
}

// How it works, then the current chain state per release read now from the V3 operator API and the chain. No sample or replayed data.
export function Overview() {
  const session = useSession()
  const steps = useReveal()
  const signedIn = session.status === 'signed-in'
  const { board, error } = useBoard(signedIn)
  const [admissions, setAdmissions] = useState<Record<string, Admission>>({})
  const releases = (board?.releases ?? []).filter((item) => board?.votes[item.releaseId] || board?.voteErrors[item.releaseId]).sort((a, b) => a.version.localeCompare(b.version))

  // Only releases the chain has a conclusion for are looked up: every lookup is written to the audit log like a Gateway check.
  useEffect(() => {
    if (!board) return
    const controller = new AbortController()
    setAdmissions({})
    for (const release of board.releases) {
      const votes = board.votes[release.releaseId], policyHash = votes?.policyHash
      if (policyHash && decidedOnChain(votes?.status, shownRound(votes))) checkAdmission(release, policyHash, controller.signal)
        .then((admission) => setAdmissions((previous) => ({ ...previous, [release.releaseId]: admission })), () => {})
    }
    return () => controller.abort()
  }, [board])

  return <div className="workspace results-workspace">
    <Sidebar active="Overview" />
    <main className="ws-main">
      <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> 개요</div><div><LanguageSwitcher /></div></header>
      <div className="ws-content results-content">
        <div className="ws-heading"><div><p>OVERVIEW</p><h1>개요</h1><span>MCPShield가 업데이트를 어떻게 검증하고 막는지, 그리고 지금 체인에 기록된 상태입니다.</span></div></div>

        <section className="ov-section" data-raw>
          <div className="ov-title"><small>HOW IT WORKS</small><h2>작동 방식</h2><span>아래로 내리면 순서대로 이어집니다 ↓</span></div>
          <ol className="how-steps" ref={steps}>{HOW.map((step) => <li className={`how-step ${step.wide ? 'banner' : step.flip ? 'flip' : ''}`} key={step.key}>
            <span className="how-rail"><i>{step.no}</i></span>
            <div className="how-body"><small>{step.kicker}</small><b>{step.title}</b><p>{step.text}</p></div>
            <div className="how-img">{React.createElement(HOW_SCENES[step.key])}</div>
          </li>)}</ol>
        </section>

        <section className="ov-section">
          <div className="ov-title"><small>LIVE STATE</small><h2>지금 상태</h2><span>모든 값은 지금 운영 API와 체인에서 읽은 것입니다.</span></div>
          {(session.status === 'error' || error) && <p className="scan-error v3-banner" role="alert">{session.status === 'error' ? session.message : error}</p>}
          {session.status === 'signed-out' ? <section className="recent panel"><div className="scan-table"><div className="history-empty"><LoginRequired /></div></div></section>
            : !board ? <section className="recent panel"><div className="scan-table"><div className="history-empty"><strong>{session.status === 'loading' ? '운영 API 세션을 확인하고 있습니다.' : '체인 기록을 불러오는 중입니다.'}</strong></div></div></section>
            : !releases.length ? <section className="recent panel"><div className="scan-table"><div className="history-empty"><strong>아직 등록된 릴리스가 없습니다.</strong><a className="ws-button primary" href="/security-scan">보안 검사 시작</a></div></div></section>
            : <><section className="v3-release-grid">{releases.map((release) => {
              const votes = board.votes[release.releaseId], votesError = board.voteErrors[release.releaseId] ?? null
              const round = shownRound(votes), admission = admissions[release.releaseId] ?? null
              const state = chainState({ votes, release, error: votesError })
              const decided = decidedOnChain(state.status, round)
              const flow = flowView({ release, votes, round, actions: board.actions, admission, votesError, scan: board.scans.find((item) => item.scanId === round?.scanId) })
              const kind = statusDotKind(state.status)
              const pendingGateway = votesError ? '조회 안 함 (체인 조회 실패)' : decided ? '조회 중' : '결론 전 · 실행 차단'
              return <article className={`panel ov-card ${kind}`} key={release.releaseId} data-release-status={state.status ?? 'NONE'} data-raw>
                <header><div><small>{release.legacyReleaseId}</small><h3><i className={`fx-dot ${kind}`} />{state.text}{state.status && <code>{state.status}</code>}</h3></div><a className="v3-link" href={`/scan-results?release=${release.releaseId}`}>결과 보기 <span>↗</span></a></header>
                {votesError ? <p className="v3-empty">체인 투표를 읽지 못했습니다. 상태를 표시하지 않으며 승인으로 간주하지 않습니다. {votesError}</p> : <>
                  <div className="ov-row"><span>검증자</span><span className="ov-lanes">{flow.lanes.map((lane) => <span key={lane.lane}><b>{lane.lane}</b><i className={`fx-dot ${laneDotKind(lane)}`} /></span>)}</span><em>{consensusCard(round).value}</em></div>
                  <div className="ov-row"><span>실행 판정</span>{admission ? <b className={`fx-chip ${admission.decision === 'ALLOW' ? 'pass' : 'fail'}`}>{admission.decision}</b> : <b className="fx-chip">{pendingGateway}</b>}<em>{admission?.reasonCode ?? ''}</em></div>
                  <details className="fx-more"><summary>검증자별 기록 보기</summary><V3FlowMap flow={flow} compact /></details>
                </>}
                <p className="v3-card-foot">{chainLabel(chainIdOf({ release, actions: board.actions, admission }))}</p>
              </article>
            })}</section>
            <p className="ov-note" data-raw>{TEAM_RUN_NOTE} {AI_WITNESS_NOTE}</p></>}
        </section>
      </div>
    </main>
  </div>
}
