// Animated scenes for the overview's how-it-works steps, redrawn after the team's intro film.
// Plain SVG with CSS keyframes (site.css, prefix sc-) and SMIL motion paths: no dependencies, no images, loops forever.
import React from 'react'

function Defs({ id }: { id: string }) {
  return <defs>
    <radialGradient id={`${id}-bg`} cx="50%" cy="64%" r="80%"><stop offset="0" stopColor="#17331a" /><stop offset=".5" stopColor="#0a130b" /><stop offset="1" stopColor="#050706" /></radialGradient>
    <radialGradient id={`${id}-red`} cx="40%" cy="35%" r="75%"><stop offset="0" stopColor="#ff5a4a" /><stop offset=".6" stopColor="#b3121c" /><stop offset="1" stopColor="#4a0a10" /></radialGradient>
    <filter id={`${id}-glow`} x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="5" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
  </defs>
}

/** A box in cabinet projection: front face at (x, y), depth going up and to the right. */
function Cube({ x, y, w, h, depth = 0.45, className = '' }: { x: number; y: number; w: number; h: number; depth?: number; className?: string }) {
  const dx = w * depth, dy = w * depth * 0.5
  return <g className={`sc-cube ${className}`}>
    <polygon className="sc-face top" points={`${x},${y} ${x + dx},${y - dy} ${x + w + dx},${y - dy} ${x + w},${y}`} />
    <polygon className="sc-face side" points={`${x + w},${y} ${x + w + dx},${y - dy} ${x + w + dx},${y + h - dy} ${x + w},${y + h}`} />
    <polygon className="sc-face front" points={`${x},${y} ${x + w},${y} ${x + w},${y + h} ${x},${y + h}`} />
  </g>
}

const Envelope = ({ x, y, w, h }: { x: number; y: number; w: number; h: number }) => <g className="sc-env">
  <rect x={x} y={y} width={w} height={h} /><path d={`M${x},${y} L${x + w / 2},${y + h * 0.58} L${x + w},${y}`} />
</g>

/** A dot that keeps travelling along a path. */
const Runner = ({ id, path, dur, begin = '0s', r = 4 }: { id: string; path: string; dur: string; begin?: string; r?: number }) =>
  <circle r={r} className="sc-runner" filter={`url(#${id}-glow)`}><animateMotion dur={dur} begin={begin} repeatCount="indefinite" path={path} /></circle>

const Label = ({ x, y, w, title, sub, tone = '' }: { x: number; y: number; w: number; title: string; sub: string; tone?: string }) => <g className={`sc-label ${tone}`}>
  <rect x={x} y={y} width={w} height="56" rx="8" />
  <text x={x + 18} y={y + 24} className="sc-label-title">{title}</text><text x={x + 18} y={y + 43} className="sc-label-sub">{sub}</text>
</g>

const svg = (id: string, width: number, height: number, label: string, children: React.ReactNode) =>
  <svg className="sc" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid slice" role="img" aria-label={label}>
    <Defs id={id} /><rect width={width} height={height} fill={`url(#${id}-bg)`} />{children}
  </svg>

/** 01 · The exact release: the package is pinned by its hashes, not its name. */
function Fingerprint() {
  const id = 'sc1'
  return svg(id, 640, 400, '배포본의 해시를 고정하는 장면', <>
    <ellipse cx="300" cy="332" rx="200" ry="46" className="sc-ring" filter={`url(#${id}-glow)`} />
    <ellipse cx="300" cy="332" rx="150" ry="33" className="sc-ring dim" />
    {/* No glow filter here: a filter on a perfectly vertical line has an empty box and hides the line. */}
    {[150, 215, 405, 460].map((x, index) => <line key={x} x1={x} y1="46" x2={x} y2="330" className="sc-beam" style={{ animationDelay: `${index * 0.5}s` }} />)}
    <Cube x={205} y={160} w={150} h={150} />
    <Envelope x={235} y={205} w={90} h={60} />
    <ellipse cx="315" cy="150" rx="135" ry="30" className="sc-scan" filter={`url(#${id}-glow)`} />
    <g className="sc-label"><rect x="392" y="96" width="222" height="112" rx="8" />
      <text x="410" y="122" className="sc-label-title">EXACT RELEASE</text>
      {['artifact  sha256:a345…f422', 'manifest  sha256:ee9…da20', 'tools     0xb701…d020'].map((row, index) => <text key={row} x="410" y={148 + index * 22} className="sc-hash" style={{ animationDelay: `${0.4 + index * 0.9}s` }}>{row}  ✓</text>)}
    </g>
  </>)
}

const NODES = [[0, -66], [46, -48], [68, 2], [44, 50], [-4, 68], [-50, 46], [-68, -4], [-44, -50], [18, -14], [-20, 16]]
const EDGES = [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 0], [8, 0], [8, 2], [8, 3], [9, 4], [9, 6], [9, 7], [8, 9], [1, 8], [5, 9]]
const LAYERS = [['01', 'STATIC ANALYSIS', '코드 규칙 검사', '위험한 코드 · 권한 변경'], ['02', 'AI SEMANTIC ANALYSIS', 'AI 의미 분석', '도구 설명 ↔ 코드의 동작 범위'], ['03', 'ISOLATED RUNTIME', 'Sandbox 실행', '시험 환경에서 유출 징후 관찰']]

/** 02 · Inside each validator: rule check, semantic analysis, sandbox run. */
function Layers() {
  const id = 'sc2'
  return svg(id, 1160, 340, '코드 규칙 검사, 의미 분석, Sandbox 실행의 세 겹 검증', <>
    {[200, 580, 960].map((cx) => <ellipse key={cx} cx={cx} cy="212" rx="118" ry="24" className="sc-pedestal" />)}
    <g><rect x="150" y="52" width="100" height="134" rx="5" className="sc-doc" />
      {[0, 1, 2, 3, 4, 5].map((row) => <line key={row} x1="166" y1={76 + row * 18} x2={166 + [62, 40, 68, 48, 70, 34][row]} y2={76 + row * 18} className="sc-line" style={{ animationDelay: `${row * 0.35}s` }} />)}
      <rect x="146" y="54" width="108" height="3" className="sc-docscan" filter={`url(#${id}-glow)`} /></g>
    <g transform="translate(580 120)">
      <ellipse rx="112" ry="24" className="sc-orbit" /><Runner id={id} path="M-112,0 a112,24 0 1,0 224,0 a112,24 0 1,0 -224,0" dur="7s" r={5} />
      <g className="sc-spin">
        {EDGES.map(([from, to]) => <line key={`${from}-${to}`} x1={NODES[from][0]} y1={NODES[from][1]} x2={NODES[to][0]} y2={NODES[to][1]} className="sc-edge" />)}
        <circle r="24" className="sc-wire" /><ellipse rx="24" ry="9" className="sc-wire" /><ellipse rx="9" ry="24" className="sc-wire" />
        {NODES.map(([x, y], index) => <circle key={index} cx={x} cy={y} r="4.5" className="sc-node" style={{ animationDelay: `${index * 0.27}s` }} filter={`url(#${id}-glow)`} />)}
      </g>
    </g>
    <g><ellipse cx="972" cy="204" rx="104" ry="21" className="sc-ring" filter={`url(#${id}-glow)`} />
      <g filter={`url(#${id}-glow)`}><Cube x={905} y={78} w={112} h={112} className="glass" /></g>
      <Cube x={940} y={118} w={46} h={46} className="core" />
      <circle cx="1026" cy="128" r="5.5" className="sc-alarm" /></g>
    {LAYERS.map(([no, kicker, title, sub], index) => { const x = 30 + index * 380; return <g key={no} className="sc-card">
      <rect x={x} y="234" width="340" height="92" rx="8" />
      <text x={x + 20} y="258" className="sc-card-kicker"><tspan className="sc-card-no">{no}</tspan>  {kicker}</text>
      <text x={x + 20} y="286" className="sc-card-title">{title}</text><text x={x + 20} y="306" className="sc-card-sub">{sub}</text>
      <rect x={x + 20} y="316" width="300" height="2" className="sc-track" /><rect x={x + 20} y="316" width="300" height="2" className="sc-fill" style={{ animationDelay: `${index * 1.8}s` }} />
    </g> })}
  </>)
}

function Tower({ x, y, w, h, lane }: { x: number; y: number; w: number; h: number; lane: string }) {
  const rows = Math.floor(h / 13)
  return <g className="sc-tower"><Cube x={x} y={y} w={w} h={h} depth={0.5} />
    {Array.from({ length: rows }, (_, row) => <line key={row} x1={x + 5} y1={y + 10 + row * 13} x2={x + w - 5} y2={y + 10 + row * 13} className="sc-window" style={{ animationDelay: `${(row * 0.19 + x * 0.01) % 3}s` }} />)}
    <text x={x + w / 2} y={y - 18} className="sc-lane">{lane}</text></g>
}

const SIGN_PATHS = { A: 'M142,300 Q230,340 300,258', B: 'M440,170 Q400,210 345,226', C: 'M520,308 Q430,330 350,258' }

/** 03 · Independent evidence: each validator checks its own copy and signs its own verdict. */
function Validators() {
  const id = 'sc3'
  return svg(id, 640, 400, '검증자 A, B, C가 각자 검사하고 서명하는 장면', <>
    {Object.values(SIGN_PATHS).map((path) => <path key={path} d={path} className="sc-wire-path" />)}
    <ellipse cx="322" cy="262" rx="58" ry="15" className="sc-pedestal" />
    {[0, 1, 2].map((ring) => <ellipse key={ring} cx="322" cy={252 - ring * 11} rx={44 - ring * 9} ry={11 - ring * 2} className="sc-stack" style={{ animationDelay: `${ring * 0.4}s` }} filter={`url(#${id}-glow)`} />)}
    <polygon points="322,196 338,212 322,228 306,212" className="sc-gem" filter={`url(#${id}-glow)`} />
    <Tower x={96} y={130} w={46} h={176} lane="A" /><Tower x={420} y={52} w={40} h={124} lane="B" /><Tower x={520} y={150} w={46} h={164} lane="C" />
    <Runner id={id} path={SIGN_PATHS.A} dur="2.6s" /><Runner id={id} path={SIGN_PATHS.B} dur="2.6s" begin="0.9s" /><Runner id={id} path={SIGN_PATHS.C} dur="2.6s" begin="1.7s" />
    {[['A', 22, 318], ['B', 478, 44], ['C', 398, 340]].map(([lane, x, y], index) => <g key={lane} className="sc-sign" style={{ animationDelay: `${index * 0.9}s` }}>
      <rect x={x} y={y} width="132" height="34" rx="6" /><text x={Number(x) + 14} y={Number(y) + 22}>{lane} · 검사 · 서명</text><path d={`M${Number(x) + 108},${Number(y) + 18} l5,5 l9,-10`} className="sc-check" /></g>)}
  </>)
}

const ORBIT = 'M530,160 a170,44 0 1,0 340,0 a170,44 0 1,0 -340,0'

/** 04 · Two of three: when two validators agree, the contract records one verdict everyone shares. */
function Quorum() {
  const id = 'sc4'
  return svg(id, 1160, 340, '세 곳 중 두 곳이 같은 판정을 내면 체인에 기록되는 장면', <>
    <path d="M300,36 Q720,-40 1160,260" className="sc-arc" filter={`url(#${id}-glow)`} /><path d="M470,330 Q760,110 1010,30" className="sc-arc thin" />
    <Runner id={id} path="M300,36 Q720,-40 1160,260" dur="5s" r={5} /><Runner id={id} path="M470,330 Q760,110 1010,30" dur="6s" begin="1.5s" />
    <clipPath id={`${id}-clip`}><rect x="36" y="22" width="130" height="150" /></clipPath>
    <g clipPath={`url(#${id}-clip)`}><g className="sc-count">{['0', '1', '2'].map((digit, index) => <text key={digit} x="40" y={160 + index * 150} className="sc-big">{digit}</text>)}</g></g>
    <text x="176" y="160" className="sc-of">/ 3</text>
    <text x="42" y="212" className="sc-quorum-line">두 곳 이상이 같은 판정을 내면</text>
    <g className="sc-verified"><rect x="40" y="232" width="200" height="34" rx="17" /><text x="140" y="254">VERIFIED</text></g>
    <text x="42" y="298" className="sc-card-kicker">SMART CONTRACT</text><text x="42" y="320" className="sc-quorum-sub">승인 또는 폐기가 체인에 기록됩니다.</text>
    <ellipse cx="700" cy="262" rx="160" ry="40" className="sc-pedestal" />
    {[0, 1, 2].map((ring) => <ellipse key={ring} cx="700" cy={244 - ring * 22} rx={118 - ring * 16} ry={30 - ring * 4} className="sc-stack" style={{ animationDelay: `${ring * 0.4}s` }} filter={`url(#${id}-glow)`} />)}
    <g className="sc-bob" filter={`url(#${id}-glow)`}><polygon points="700,108 742,138 726,186 674,186 658,138" className="sc-gem" /><path d="M700,108 L700,186 M658,138 L742,138 M674,186 L700,138 L726,186" className="sc-gem-line" /></g>
    <path d={ORBIT} className="sc-orbit" /><Runner id={id} path={ORBIT} dur="6s" r={5} />
    <Label x={826} y={62} w={262} title="RELEASE REGISTRY" sub="파일 대신, 서명과 증거 hash" />
    {['A', 'B', 'C'].map((lane, index) => <g key={lane} className={`sc-chip ${lane.toLowerCase()}`}><rect x={770 + index * 128} y="284" width="112" height="32" rx="16" /><text x={826 + index * 128} y="305">{lane}  SIGNED</text></g>)}
  </>)
}

const Desks = () => <g className="sc-desks">{[[58, 262], [116, 238], [174, 214]].map(([x, y]) => <g key={x}>
  <rect x={x} y={y} width="36" height="25" rx="2" /><path d={`M${x + 18},${y + 25} v9 M${x + 6},${y + 34} h24`} /><ellipse cx={x + 18} cy={y + 46} rx="26" ry="6" /></g>)}</g>

const Package = ({ dim = false }: { dim?: boolean }) => <g className={dim ? 'sc-dim' : ''}>
  <Cube x={468} y={176} w={104} h={132} depth={0.4} /><Envelope x={488} y={200} w={64} h={42} />
  {[0, 1, 2, 3].map((row) => <line key={row} x1="488" y1={260 + row * 10} x2="552" y2={260 + row * 10} className="sc-line still" />)}</g>

/** 05 · Check before execution: the Gateway re-reads the verdict right before the tool runs. */
function Gateway() {
  const id = 'sc5', path = 'M112,258 L330,206 L474,232'
  return svg(id, 640, 400, 'Gateway가 실행 직전에 판정을 확인하고 통과시키는 장면', <>
    <ellipse cx="535" cy="318" rx="100" ry="21" className="sc-ring" filter={`url(#${id}-glow)`} /><ellipse cx="330" cy="296" rx="84" ry="18" className="sc-pedestal" />
    <Desks /><path d={path} className="sc-wire-path" /><Package />
    <ellipse cx="330" cy="206" rx="40" ry="82" className="sc-gate" filter={`url(#${id}-glow)`} /><ellipse cx="330" cy="206" rx="28" ry="66" className="sc-gate-inner" />
    {['0s', '0.8s', '1.6s'].map((begin) => <Runner key={begin} id={id} path={path} dur="2.4s" begin={begin} />)}
    <Label x={372} y={74} w={228} title="GATEWAY" sub="HASH MATCH · ALLOW" />
  </>)
}

/** 06 · Revoked means blocked: a revoked release is refused before its process starts. */
function Blocked() {
  const id = 'sc6', path = 'M112,258 L300,213'
  return svg(id, 640, 400, '폐기된 업데이트가 실행 전에 차단되는 장면', <>
    <ellipse cx="330" cy="296" rx="84" ry="18" className="sc-pedestal" /><Desks /><path d="M112,258 L330,206" className="sc-wire-path" /><Package dim />
    <ellipse cx="330" cy="206" rx="40" ry="82" className="sc-stop" fill={`url(#${id}-red)`} filter={`url(#${id}-glow)`} />
    <ellipse cx="306" cy="212" rx="18" ry="34" className="sc-ripple" /><ellipse cx="306" cy="212" rx="18" ry="34" className="sc-ripple" style={{ animationDelay: '0.8s' }} />
    {['0s', '0.8s'].map((begin) => <circle key={begin} r="4" className="sc-runner" filter={`url(#${id}-glow)`}>
      <animateMotion dur="1.6s" begin={begin} repeatCount="indefinite" path={path} /><animate attributeName="opacity" values="1;1;0" keyTimes="0;0.86;1" dur="1.6s" begin={begin} repeatCount="indefinite" /></circle>)}
    <Label x={372} y={74} w={236} title="EXECUTION BLOCKED" sub="REVOKED · Gateway 차단" tone="fail" />
  </>)
}

export const HOW_SCENES: Record<string, () => React.ReactElement> = { fingerprint: Fingerprint, layers: Layers, validators: Validators, quorum: Quorum, gateway: Gateway, blocked: Blocked }
