'use client'

import { useRef, useState } from 'react'

const nav = [
  ['소개', '#why'],
  ['주요 기능', '#product'],
  ['작동 방식', '#how'],
  ['보안 체험', '#product'],
]

const Logo = () => (
  <a className="logo" href="#top" aria-label="MCPShield 홈">
    <svg viewBox="0 0 28 28" aria-hidden="true"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21" /><path d="M6 17h16" /></svg>
    <span>MCP<span>SHIELD</span></span>
  </a>
)

const ButtonLink = ({ children, secondary = false, href = '#product' }: { children: React.ReactNode; secondary?: boolean; href?: string }) => (
  <a href={href} className={`button ${secondary ? 'button-secondary' : ''}`}>{children}</a>
)

function Header() {
  const [open, setOpen] = useState(false)
  return <header className="header">
    <div className="nav-shell">
      <Logo />
      <nav className={open ? 'nav-links open' : 'nav-links'} aria-label="주요 메뉴">
        {nav.map(([label, href]) => <a key={label} href={href} onClick={() => setOpen(false)}>{label}</a>)}
      </nav>
      <a className="nav-cta" href="/security-scan">무료 체험하기 <span>↗</span></a>
      <button className="menu" aria-label="메뉴 열기" aria-expanded={open} onClick={() => setOpen(!open)}><i /><i /></button>
    </div>
  </header>
}

function OpticalField() {
  const field = useRef<HTMLDivElement>(null)
  const move = (event: React.PointerEvent<HTMLDivElement>) => {
    const box = event.currentTarget.getBoundingClientRect()
    field.current?.style.setProperty('--mx', `${((event.clientX - box.left) / box.width - .5) * 22}px`)
    field.current?.style.setProperty('--my', `${((event.clientY - box.top) / box.height - .5) * 16}px`)
  }
  return <div className="optical-field" ref={field} onPointerMove={move} aria-hidden="true">
    <div className="aura aura-wide" />
    <div className="aura aura-mint" />
    <div className="aura aura-deep" />
    <div className="aura-core" />
    <div className="hero-vignette" />
  </div>
}

function Hero() {
  return <main id="top" className="hero shell">
    <OpticalField />
    <div className="hero-copy">
      <p className="eyebrow">INTELLIGENCE BEFORE EXECUTION</p>
      <h1>AI가 실행하기 전에,<br /><em>위험을 발견하다.</em></h1>
      <p className="hero-lede">AI가 사용하는 외부 도구의 위험을 검증하고,<br />안전한 실행을 위한 기준을 만듭니다.</p>
      <div className="actions"><ButtonLink href="/security-scan">보안 체험 시작하기 <span>↗</span></ButtonLink><ButtonLink secondary href="#why">MCPShield 알아보기</ButtonLink></div>
    </div>
  </main>
}

function Footer() {
  return <footer className="footer shell">
    <div><Logo /><p>Verify first. Execute safely.</p></div>
    <div className="footer-links"><span>PRODUCT</span><a href="#top">소개</a><a href="#top">보안 체험</a><a href="#top">작동 방식</a></div>
    <div className="footer-links"><span>CONNECT</span><a href="#top">GitHub ↗</a><a href="mailto:hello@mcpshield.ai">Contact</a></div>
    <small>© 2025 MCPShield. All rights reserved.</small>
  </footer>
}

export function Landing() {
  return <><Header /><Hero /><Footer /></>
}
