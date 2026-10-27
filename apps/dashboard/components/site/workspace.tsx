import Link from 'next/link'

export type IconName = 'grid' | 'scan' | 'result' | 'logs' | 'history' | 'settings' | 'plus' | 'play' | 'check' | 'alert' | 'chevron' | 'arrow' | 'download' | 'refresh'

export function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>,
    scan: <><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /><circle cx="12" cy="12" r="3" /></>,
    result: <><path d="M5 3h14v18H5z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></>,
    logs: <><path d="M7 5h14M7 12h14M7 19h14" /><circle cx="3" cy="5" r=".5" fill="currentColor" /><circle cx="3" cy="12" r=".5" fill="currentColor" /><circle cx="3" cy="19" r=".5" fill="currentColor" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></>,
    plus: <path d="M12 5v14M5 12h14" />,
    play: <path d="m9 6 9 6-9 6V6Z" />,
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M12 3 2.8 20h18.4L12 3Z" /><path d="M12 9v5M12 17h.01" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
    arrow: <path d="m5 12 6-6m-6 6 6 6M5 12h14" />,
    download: <><path d="M12 3v12m0 0 5-5m-5 5-5-5" /><path d="M5 20h14" /></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6.1 8A7 7 0 0 1 18 6l2 2M18 16a7 7 0 0 1-12 2l-2-2" /></>,
  }
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

export type NavLabel = 'Overview' | 'Security Scan' | 'Scan Results' | 'Validation Logs' | 'History' | 'Settings'

const navItems: [IconName, NavLabel, string][] = [
  ['grid', 'Overview', '/overview'], ['scan', 'Security Scan', '/security-scan'], ['result', 'Scan Results', '/scan-results'],
  ['logs', 'Validation Logs', '/scan-results#evidence'], ['history', 'History', '/history'], ['settings', 'Settings', '/console'],
]

export function Sidebar({ active, className = '' }: { active: NavLabel; className?: string }) {
  const item = ([icon, label, href]: [IconName, NavLabel, string]) => <Link className={label === active ? 'active' : ''} href={href} key={label}><Icon name={icon} /><span>{label}</span></Link>
  return <aside className={`ws-sidebar ${className}`.trim()}>
    <Link className="ws-brand" href="/"><svg viewBox="0 0 28 28"><path d="M3 21 9.5 7l4.5 9 4.5-9L25 21M6 17h16" /></svg><span>MCP<b>SHIELD</b></span></Link>
    <div className="ws-environment"><i /> Demo Environment <Icon name="chevron" /></div>
    <nav aria-label="Workspace navigation">
      <small>WORKSPACE</small>
      {navItems.slice(0, 4).map(item)}
      <small>MANAGE</small>
      {navItems.slice(4).map(item)}
    </nav>
    <div className="ws-system"><span><i /> LIVE DEMO</span><small>LOCAL_DEMO ledger · 테스트넷 아님</small></div>
    <div className="ws-profile"><span>MK</span><div><b>Minjun Kim</b><small>Developer workspace</small></div><button aria-label="Profile menu">•••</button></div>
  </aside>
}
