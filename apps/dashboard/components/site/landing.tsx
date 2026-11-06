'use client'

import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import dynamic from 'next/dynamic'
import { AnimatePresence, motion, useInView, useMotionValue, useReducedMotion, useScroll, useSpring, useTransform, type MotionValue } from 'motion/react'
import { animate, createTimeline, stagger } from 'animejs'
import { AI_WITNESS_NOTE, TEAM_RUN_NOTE } from './v3-model'
import { Icon, type IconName } from './workspace'

// Interaction patterns follow KokonutUI's Swipe Tabs, Magnet Button and Split Flap Text (kokonutui.com, MIT), rebuilt here on Motion with this site's CSS.
const HeroScene = dynamic(() => import('./hero-scene').then((module) => module.HeroScene), { ssr: false })

const REPOSITORY = 'https://github.com/sihoon-0077/MCPShield'

const nav = [
  ['작동 방식', '/overview'],
  ['보안 검사', '/security-scan'],
  ['검사 기록', '/history'],
  ['운영 콘솔', '/console'],
  ['GitHub', REPOSITORY],
]

const outside = (href: string) => href.startsWith('https://') ? { target: '_blank', rel: 'noreferrer' } : {}

const Logo = () => (
  <a className="lp-logo" href="#top" aria-label="MCPShield 홈">
    <svg viewBox="0 0 28 28" aria-hidden="true"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg>
    <span>MCP<span>SHIELD</span></span>
  </a>
)

/** A link that leans toward the pointer while it is hovered. */
function Magnetic({ href, className, children }: { href: string; className: string; children: React.ReactNode }) {
  const x = useMotionValue(0), y = useMotionValue(0)
  const spring = { stiffness: 260, damping: 18, mass: 0.6 }
  const left = useSpring(x, spring), top = useSpring(y, spring)
  const move = (event: React.PointerEvent<HTMLAnchorElement>) => {
    const box = event.currentTarget.getBoundingClientRect()
    x.set((event.clientX - box.left - box.width / 2) * 0.22); y.set((event.clientY - box.top - box.height / 2) * 0.3)
  }
  return <motion.a href={href} className={className} style={{ x: left, y: top }} onPointerMove={move} onPointerLeave={() => { x.set(0); y.set(0) }} whileTap={{ scale: 0.97 }} {...outside(href)}>{children}</motion.a>
}

const Reveal = ({ children, className, delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) => (
  <motion.div className={className} initial={{ opacity: 0, y: 26 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: '-70px' }} transition={{ duration: 0.7, delay, ease: [0.2, 0.7, 0.2, 1] }}>{children}</motion.div>
)

function Header() {
  const [open, setOpen] = useState(false)
  const { scrollYProgress } = useScroll()
  const scaleX = useSpring(scrollYProgress, { stiffness: 140, damping: 30 })
  return <header className="lp-header">
    <motion.i className="lp-progress" style={{ scaleX }} aria-hidden="true" />
    <div className="lp-shell lp-nav">
      <Logo />
      <nav className={open ? 'lp-links open' : 'lp-links'} aria-label="주요 메뉴">
        {nav.map(([label, href]) => <a key={label} href={href} onClick={() => setOpen(false)} {...outside(href)}>{label}</a>)}
      </nav>
      <a className="lp-nav-cta" href="/security-scan">보안 검사 시작 <Icon name="next" /></a>
      <button className="lp-menu" aria-label="메뉴 열기" aria-expanded={open} onClick={() => setOpen(!open)}><i /><i /></button>
    </div>
  </header>
}

const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.@-'

/** A split-flap row: each cell runs through a few glyphs before it lands on its letter, left to right. */
function Flap({ text, length, className = '' }: { text: string; length: number; className?: string }) {
  const target = text.padEnd(length)
  const [shown, setShown] = useState(target)
  const still = useReducedMotion()
  useEffect(() => {
    if (still) { setShown(target); return }
    let tick = 0
    const timer = setInterval(() => {
      tick += 1
      setShown([...target].map((char, index) => tick > 3 + index * 1.4 ? char : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]).join(''))
      if (tick > 4 + length * 1.4) clearInterval(timer)
    }, 52)
    return () => clearInterval(timer)
  }, [target, length, still])
  return <span className={`lp-flap ${className}`} role="img" aria-label={text}>{[...shown].map((char, index) => <i key={index} aria-hidden="true"><b key={char}>{char}</b></i>)}</span>
}

// The two reviewed fixtures and how the demo decides them. Illustration of the expected run; live records are on the scan screens.
const CASES = {
  '1.0.0': { tag: '정상 버전', title: '메일 목록을 읽는 기준 버전', voteText: '통과', count: '3/3 PASS', status: 'VERIFIED', statusText: '승인', gateway: 'ALLOW', reason: 'RELEASE_VERIFIED', tone: 'pass',
    findings: [] as string[], note: '검증자 둘이 통과에 서명한 순간 승인이 확정됩니다. Gateway는 이 버전의 실행을 허용합니다.' },
  '1.0.1': { tag: '악성 업데이트', title: '데이터를 몰래 내보내는 업데이트', voteText: '불합격', count: '3/3 FAIL', status: 'REVOKED', statusText: '폐기', gateway: 'BLOCK', reason: 'RELEASE_REVOKED', tone: 'fail',
    findings: ['CANARY_EXFILTRATION', 'SENSITIVE_FILE_READ', 'UNDECLARED_EGRESS', 'UNSAFE_MODULE_LOAD'], note: '둘이 불합격에 서명하면 폐기가 확정됩니다. 같은 파일은 다시 승인할 수 없고, Gateway는 실행을 막습니다.' },
} as const
type CaseKey = keyof typeof CASES
const CASE_KEYS = Object.keys(CASES) as CaseKey[]

function Board() {
  const [index, setIndex] = useState(0)
  useEffect(() => { const timer = setInterval(() => setIndex((value) => (value + 1) % CASE_KEYS.length), 4200); return () => clearInterval(timer) }, [])
  const key = CASE_KEYS[index], item = CASES[key]
  return <div className="lp-board" data-raw>
    <small>GATEWAY · 실행 직전 판정</small>
    <div><Flap text={`MAIL-MCP@${key}`} length={14} /><Flap text={item.gateway} length={5} className={item.tone} /></div>
  </div>
}

const HEADLINE = ['AI가 실행하기 전에,', '위험을 발견하다.']
const FACTS: [string, string][] = [['2-of-3', '검증자 셋 중 둘의 서명으로 결론'], ['EIP-712', '검증자가 자기 키로 서명한 투표'], ['실행 직전', 'Gateway가 판정을 다시 확인']]

function Hero() {
  const title = useRef<HTMLHeadingElement>(null)
  // Letters rise out of their own line, one after another.
  useLayoutEffect(() => {
    const letters = title.current?.querySelectorAll('.lp-char > i')
    if (!letters?.length || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const rise = animate(letters, { translateY: ['108%', '0%'], duration: 950, delay: stagger(28, { start: 140 }), ease: 'out(4)' })
    return () => { rise.revert() }
  }, [])
  return <main id="top" className="lp-hero lp-shell">
    <div className="lp-hero-copy">
      <p className="lp-kicker"><i /> MCP 도구 업데이트 검증</p>
      <h1 ref={title} aria-label={HEADLINE.join(' ')}>
        {HEADLINE.map((line, row) => <span className={`lp-line ${row ? 'accent' : ''}`} key={line} aria-hidden="true">
          {line.split(' ').map((word, at) => <span className="lp-word" key={at}>{[...word].map((char, index) => <span className="lp-char" key={index}><i>{char}</i></span>)}</span>)}
        </span>)}
      </h1>
      <motion.p className="lp-lede" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.75, duration: 0.7 }}>
        MCP 도구는 업데이트 한 번으로 전혀 다른 프로그램이 될 수 있습니다. MCPShield는 배포본의 지문을 고정하고, 검증자 셋이 각자 다시 검사해 서명한 결과가 있을 때만 실행을 허용합니다.
      </motion.p>
      <motion.div className="lp-actions" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.9, duration: 0.7 }}>
        <Magnetic href="/security-scan" className="lp-button primary">보안 검사 시작하기 <Icon name="next" /></Magnetic>
        <a href="/overview" className="lp-button">작동 방식 보기</a>
        <a href={REPOSITORY} className="lp-text-link" target="_blank" rel="noreferrer"><Icon name="github" /> GitHub</a>
      </motion.div>
      <motion.dl className="lp-facts" initial="off" animate="on" variants={{ on: { transition: { staggerChildren: 0.09, delayChildren: 1.05 } } }} data-raw>
        {FACTS.map(([value, text]) => <motion.div key={value} variants={{ off: { opacity: 0, y: 12 }, on: { opacity: 1, y: 0 } }}><dt>{value}</dt><dd>{text}</dd></motion.div>)}
      </motion.dl>
    </div>
    <div className="lp-stage">
      <HeroScene />
      <Board />
    </div>
  </main>
}

const STATEMENT = '어제 승인한 도구가 오늘 조용히 바뀌어도, AI는 이름만 보고 그대로 실행합니다.'
const WHY: [IconName, string, string][] = [
  ['package', '이름은 그대로, 내용은 다르게', 'mail-mcp 1.0.0은 메일 목록만 읽습니다. 1.0.1은 같은 이름으로, 데이터를 밖으로 내보내는 코드를 품고 옵니다.'],
  ['scales', '한 곳의 검사로는 부족합니다', '검사하는 곳이 하나뿐이면 그곳이 틀렸을 때 막을 방법이 없습니다. 그래서 셋이 따로 검사하고, 둘 이상이 같아야 결론이 납니다.'],
  ['gate', '승인은 실행 직전에 다시 확인', 'Gateway는 도구를 실행하기 직전에 체인의 판정을 다시 조회합니다. 승인이 폐기됐다면 그 자리에서 멈춥니다.'],
]

function Word({ children, progress, range }: { children: string; progress: MotionValue<number>; range: [number, number] }) {
  const opacity = useTransform(progress, range, [0.16, 1])
  return <motion.span style={{ opacity }}>{children} </motion.span>
}

// The statement lights up word by word as it is scrolled through.
function Problem() {
  const ref = useRef<HTMLHeadingElement>(null)
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start 0.88', 'end 0.5'] })
  const words = STATEMENT.split(' ')
  return <section className="lp-section lp-shell" id="why">
    <p className="lp-kicker"><i /> 왜 필요한가</p>
    <h2 className="lp-statement" ref={ref} aria-label={STATEMENT}>{words.map((word, index) => <Word key={index} progress={scrollYProgress} range={[index / words.length, (index + 1) / words.length]}>{word}</Word>)}</h2>
    <div className="lp-why">{WHY.map(([icon, title, text], index) => <Reveal key={title} delay={index * 0.08}><span className="lp-why-icon"><Icon name={icon} /></span><h3>{title}</h3><p>{text}</p></Reveal>)}</div>
  </section>
}

const LANES = ['A', 'B', 'C']

function CaseFlow({ version }: { version: CaseKey }) {
  const item = CASES[version]
  const ref = useRef<HTMLDivElement>(null)
  const seen = useInView(ref, { once: true, margin: '-120px' })
  // Release, then the three votes one by one, then the verdict.
  useLayoutEffect(() => {
    const root = ref.current
    if (!root || !seen || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const pick = (name: string) => root.querySelectorAll(`[data-seq="${name}"]`)
    const flow = createTimeline({ defaults: { ease: 'out(3)', duration: 440 } })
      .add(pick('release'), { opacity: [0, 1], translateX: [-16, 0] })
      .add(pick('vote'), { opacity: [0, 1], translateX: [-12, 0], delay: stagger(240) }, '-=120')
      .add(pick('chip'), { opacity: [0, 1], scale: [0.5, 1], delay: stagger(240), ease: 'outBack(2.2)' }, '<<+=200')
      .add(pick('verdict'), { opacity: [0, 1], translateY: [20, 0], duration: 560 }, '-=80')
    return () => { flow.revert() }
  }, [version, seen])
  return <div className={`lp-flow ${item.tone}`} ref={ref} style={{ visibility: seen ? 'visible' : 'hidden' }} data-raw>
    <div className="lp-flow-col" data-seq="release">
      <small>01 · 릴리스 등록</small>
      <b className="lp-flow-name">mail-mcp<code>{version}</code></b>
      <p>{item.title}</p>
      <span className="lp-flow-meta"><Icon name="fingerprint" /> 배포본 지문을 체인에 고정</span>
    </div>
    <span className="lp-flow-arrow" aria-hidden="true"><Icon name="next" /></span>
    <div className="lp-flow-col">
      <small>02 · 검증자 투표</small>
      <ul>{LANES.map((lane) => <li key={lane} data-seq="vote"><b>{lane}</b><span>검증자 {lane}</span><em className={`fx-chip ${item.tone}`} data-seq="chip">{item.voteText}</em></li>)}</ul>
      <span className="lp-flow-meta"><Icon name="sign" /> {item.count} · 둘이 모이면 결론</span>
    </div>
    <span className="lp-flow-arrow" aria-hidden="true"><Icon name="next" /></span>
    <div className="lp-flow-col verdict" data-seq="verdict">
      <small>03 · Gateway 실행 판정</small>
      <strong>{item.gateway}</strong>
      <code>{item.reason}</code>
      <p>체인 상태 {item.status} · {item.statusText}</p>
    </div>
  </div>
}

function Cases() {
  const [version, setVersion] = useState<CaseKey>('1.0.0')
  const item = CASES[version]
  return <section className="lp-section lp-cases" id="cases">
    <div className="lp-shell">
      <div className="lp-section-head">
        <div><p className="lp-kicker"><i /> 두 버전, 두 결과</p><h2>같은 이름의 도구가<br />다른 판정을 받습니다.</h2></div>
        <p>시연에 쓰는 mail-mcp의 두 버전입니다. 아래는 시연이 진행되는 순서를 그린 그림이고, 실제 기록은 검사를 돌린 뒤 결과 화면에 표시됩니다.</p>
      </div>
      <div className="lp-tabs" role="tablist" aria-label="버전 선택">
        {CASE_KEYS.map((key) => <button type="button" role="tab" aria-selected={version === key} key={key} className={version === key ? 'on' : ''} onClick={() => setVersion(key)} data-raw>
          {version === key && <motion.span className="lp-tab-pill" layoutId="lp-tab-pill" transition={{ type: 'spring', stiffness: 380, damping: 34 }} />}
          <span><code>{key}</code>{CASES[key].tag}</span>
        </button>)}
      </div>
      <AnimatePresence mode="wait" initial={false}>
        <motion.div key={version} className="lp-case" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: 0.28 }}>
          <CaseFlow version={version} />
          <div className="lp-case-foot">
            <p>{item.note}</p>
            {item.findings.length > 0 && <ul className="lp-findings" data-raw aria-label="검증자가 찾은 항목">{item.findings.map((code) => <li key={code}>{code}</li>)}</ul>}
            <a className="lp-text-link" href={`/security-scan?version=${version}`}>이 버전 직접 검사하기 <Icon name="next" /></a>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  </section>
}

const STEPS: [IconName, string, string][] = [
  ['fingerprint', '지문을 고정한다', '이름이 아니라 배포본 파일의 지문을 체인에 등록합니다. 한 글자만 달라도 다른 릴리스입니다.'],
  ['validators', '각자 검사하고, 각자 서명한다', '검증자 A·B·C가 같은 파일을 따로 다시 검사하고 자기 키로 투표에 서명합니다. 둘 이상이 같으면 결론이 납니다.'],
  ['shield', '실행 직전에 확인한다', 'Gateway가 도구를 실행하기 직전에 판정을 조회해, 승인된 릴리스만 통과시킵니다.'],
]

function How() {
  const ref = useRef<HTMLOListElement>(null)
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start 0.85', 'start 0.35'] })
  return <section className="lp-section lp-shell" id="how">
    <div className="lp-section-head">
      <div><p className="lp-kicker"><i /> 작동 방식</p><h2>세 단계로 막습니다.</h2></div>
      <p>등록, 검증, 실행 확인. 각 단계의 기록은 체인에 남아 다시 확인할 수 있습니다.</p>
    </div>
    <ol className="lp-steps" ref={ref}>
      <motion.i className="lp-steps-line" style={{ scaleX: scrollYProgress }} aria-hidden="true" />
      {STEPS.map(([icon, title, text], index) => <li key={title}><Reveal delay={index * 0.1}>
        <span className="lp-step-no">{String(index + 1).padStart(2, '0')}</span>
        <span className="lp-step-icon"><Icon name={icon} /></span>
        <h3>{title}</h3><p>{text}</p>
      </Reveal></li>)}
    </ol>
    <a className="lp-text-link" href="/overview">여섯 장면으로 자세히 보기 <Icon name="next" /></a>
  </section>
}

const LIMITS = [TEAM_RUN_NOTE, AI_WITNESS_NOTE, '이 화면은 도구를 실행하지 않습니다. 실행 여부는 실제 Gateway가 실행 직전에 판정을 다시 조회해 결정합니다.']

function Limits() {
  return <section className="lp-section lp-limits">
    <div className="lp-shell lp-limits-grid">
      <div><p className="lp-kicker"><i /> 솔직하게</p><h2>이 시연이<br />주장하지 않는 것.</h2></div>
      <ul>{LIMITS.map((text, index) => <li key={text}><Reveal delay={index * 0.08}><span>{String(index + 1).padStart(2, '0')}</span><p>{text}</p></Reveal></li>)}</ul>
    </div>
  </section>
}

function Closing() {
  return <section className="lp-closing lp-shell">
    <Reveal><h2>업데이트를 믿기 전에,<br />먼저 검사하세요.</h2></Reveal>
    <div className="lp-actions"><Magnetic href="/security-scan" className="lp-button primary">보안 검사 시작하기 <Icon name="next" /></Magnetic><a href={REPOSITORY} className="lp-button" target="_blank" rel="noreferrer"><Icon name="github" /> GitHub에서 코드 보기</a></div>
  </section>
}

function Footer() {
  return <footer className="lp-footer lp-shell">
    <div><Logo /><p>Verify first. Execute safely.</p></div>
    <div className="lp-footer-links"><span>PRODUCT</span><a href="/overview">작동 방식</a><a href="/security-scan">보안 검사</a><a href="/history">검사 기록</a><a href="/console">운영 콘솔</a></div>
    <div className="lp-footer-links"><span>CONNECT</span><a href={REPOSITORY} target="_blank" rel="noreferrer">GitHub</a></div>
    <small>© 2026 MCPShield.</small>
  </footer>
}

export function Landing() {
  return <div className="lp"><Header /><Hero /><Problem /><Cases /><How /><Limits /><Closing /><Footer /></div>
}
