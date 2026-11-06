'use client'

import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { animate as slide } from 'motion'
import { animate, stagger, utils } from 'animejs'
import Link from 'next/link'
import { controlApi } from '../../lib/control-client'
import { chainLabel } from './v3-model'
import { ICONS, type IconName } from './icons'

export type { IconName }

/** Phosphor icons from the Iconify set (see icons.ts): inline SVG, nothing fetched at runtime. */
export function Icon({ name }: { name: IconName }) {
  return <svg viewBox="0 0 256 256" aria-hidden="true" style={{ fill: 'currentColor', stroke: 'none' }} dangerouslySetInnerHTML={{ __html: ICONS[name] }} />
}

export type NavLabel = 'Overview' | 'Security Scan' | 'Scan Results' | 'History' | 'Settings'

// Keys stay English (pages pass them as `active`); the shown text is Korean and the EN toggle translates it back.
const navItems: [IconName, NavLabel, string, string][] = [
  ['grid', 'Overview', '/overview', '개요'], ['scan', 'Security Scan', '/security-scan', '보안 검사'], ['result', 'Scan Results', '/scan-results', '검사 결과'],
  ['history', 'History', '/history', '검사 기록'], ['settings', 'Settings', '/console', '운영 콘솔'],
]

type Shell = { state: 'loading' } | { state: 'signed-out' } | { state: 'signed-in'; tenantId: string; role: string; chainId: number | null } | { state: 'error' }

/** Who is signed in to the operator API and which chain its records come from, read on every mount (no cache across pages).
 *  While signed out it asks again every few seconds, so a login made on /console shows up here without a reload. */
function useShell(): Shell {
  const [shell, setShell] = useState<Shell>({ state: 'loading' })
  useEffect(() => {
    const controller = new AbortController(), signal = controller.signal
    let timer: ReturnType<typeof setTimeout> | undefined
    const read = () => controlApi<{ tenantId: string; role: string }>('session', undefined, 'GET', undefined, signal)
      .then(async (session) => {
        const actions = await controlApi<{ items: { chainId: number }[] }>('chain/actions', undefined, 'GET', undefined, signal).catch(() => ({ items: [] }))
        if (!signal.aborted) setShell({ state: 'signed-in', tenantId: session.tenantId, role: session.role, chainId: actions.items[0]?.chainId ?? null })
      })
      .catch((error) => {
        if (signal.aborted) return
        const signedOut = (error as { status?: number })?.status === 401
        setShell({ state: signedOut ? 'signed-out' : 'error' })
        timer = setTimeout(read, signedOut ? 2500 : 5000)
      })
    void read()
    return () => { controller.abort(); if (timer) clearTimeout(timer) }
  }, [])
  return shell
}

// Where the marker sat on the previous page, so it slides to the new item instead of jumping.
let lastPill: { top: number; height: number } | null = null

/** The block behind the active sidebar item. Every page mounts its own sidebar, so the start position is remembered across pages. */
function NavPill({ active }: { active: NavLabel }) {
  const ref = useRef<HTMLSpanElement>(null)
  useLayoutEffect(() => {
    const pill = ref.current, link = pill?.parentElement?.querySelector<HTMLElement>('a.active')
    if (!pill || !link) return
    const to = { top: link.offsetTop, height: link.offsetHeight }, from = lastPill ?? to
    lastPill = to
    pill.style.opacity = '1'
    const controls = slide(pill, { y: [from.top, to.top], height: [from.height, to.height] }, { type: 'spring', stiffness: 420, damping: 38 })
    return () => controls.stop()
  }, [active])
  return <span className="ws-nav-pill" ref={ref} aria-hidden="true" />
}

/** The sections of a workspace page rise in one after another when the page opens. */
function useContentEntrance() {
  useLayoutEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const sections = document.querySelectorAll('.ws-content > *')
    if (!sections.length) return
    const entrance = animate(sections, { opacity: [0, 1], translateY: [16, 0], duration: 560, delay: stagger(70), ease: 'out(3)', onComplete: (self) => utils.cleanInlineStyles(self) })
    return () => { entrance.revert() }
  }, [])
}

export function Sidebar({ active, className = '' }: { active: NavLabel; className?: string }) {
  const shell = useShell()
  useContentEntrance()
  const item = ([icon, label, href, text]: [IconName, NavLabel, string, string]) => <Link className={label === active ? 'active' : ''} href={href} key={label}><Icon name={icon} /><span>{text}</span></Link>
  return <aside className={`ws-sidebar ${className}`.trim()}>
    <Link className="ws-brand" href="/"><svg viewBox="0 0 28 28"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg><span>MCP<b>SHIELD</b></span></Link>
    <div className="ws-environment" data-raw><i className={shell.state === 'signed-in' ? '' : 'off'} /> {shell.state === 'signed-in' ? (shell.chainId === null ? '체인 기록 없음' : chainLabel(shell.chainId)) : shell.state === 'loading' ? '체인 확인 중' : '체인: 로그인 후 표시'}</div>
    <nav aria-label="Workspace navigation">
      <NavPill active={active} />
      <small>워크스페이스</small>
      {navItems.slice(0, 3).map(item)}
      <small>관리</small>
      {navItems.slice(3).map(item)}
    </nav>
    <div className="ws-system" data-raw>{shell.state === 'signed-in'
      ? <><span><i /> 운영 API 연결됨</span><small>{shell.tenantId} · {shell.role}</small></>
      : shell.state === 'error' ? <><span><i className="off" /> 운영 API 연결 실패</span><small>스택이 실행 중인지 확인</small></>
      : shell.state === 'loading' ? <><span><i className="off" /> 운영 API 확인 중</span><small>세션 조회 중</small></>
      : <><span><i className="off" /> 운영 API 로그인 필요</span><small><a href="/console">운영 콘솔에서 로그인</a></small></>}</div>
  </aside>
}
