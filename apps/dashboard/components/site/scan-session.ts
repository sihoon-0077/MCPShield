// Client for the judge demo session API (`/api/judge` → backend `/api/demo`), plus the
// per-browser scan history the workspace screens share. Sessions live 15 minutes on the
// backend, so each record keeps the last session snapshot it received.

export type Target = '1.0.0' | '1.0.1'
export type Finding = { code: string; severity: string; stage: string; message: string }
export type Vote = { validator: string; address: string; releaseId: string; decision: string; signatureHash: string; at?: string }
export type Execution = { releaseId: string; decision: 'ALLOW' | 'BLOCK'; spawnAttempted: boolean; reasonCode?: string; result?: unknown; at: string }
export type DemoSession = {
  sessionId: string; createdAt: string; expiresAt: string; step: number; nextAction: string | null; complete: boolean
  source: string; synthetic: boolean; ledgerMode: string; selectedRelease: string
  releases: { releaseId: string; scanStatus: string; status: string }[]
  findings: Finding[]; votes: Vote[]; executions: Execution[]; events: { at: string; type: string; detail: string }[]
}
export type ScanStatus = 'RUNNING' | 'ALLOWED' | 'BLOCKED' | 'FAILED'
export type ScanRecord = {
  sessionId: string; target: Target; status: ScanStatus; startedAt: string; updatedAt: string
  // Findings are appended per scan; for 1.0.1 the first N belong to the 1.0.0 baseline scan.
  baselineFindingCount: number | null
  session: DemoSession; error?: string
}

export const ACTIONS: [string, string][] = [
  ['SCAN_SAFE', '기준 버전 mail-mcp@1.0.0 스캔'],
  ['VOTE_SAFE_A', '검증자 A 서명 · 1.0.0'],
  ['VOTE_SAFE_B', '검증자 B 서명 · 1.0.0'],
  ['RUN_SAFE', 'Gateway 실행 · 1.0.0'],
  ['SELECT_MALICIOUS', '업데이트 후보 mail-mcp@1.0.1 선택'],
  ['SCAN_MALICIOUS', '후보 mail-mcp@1.0.1 스캔 · 기준 버전과 비교'],
  ['VOTE_FAIL_A', '검증자 A 판정 · 1.0.1'],
  ['VOTE_FAIL_B', '검증자 B 판정 · 1.0.1'],
  ['RUN_MALICIOUS', 'Gateway 실행 시도 · 1.0.1'],
]

// Action indexes per target: 1.0.1 is always checked after the 1.0.0 baseline is verified.
export const PLAN: Record<Target, { scan: number; votes: [number, number]; run: number; total: number }> = {
  '1.0.0': { scan: 0, votes: [1, 2], run: 3, total: 4 },
  '1.0.1': { scan: 5, votes: [6, 7], run: 8, total: 9 },
}

export const STAGES: [string, string][] = [
  ['Artifact Fetch', '패키지 정보 수집'],
  ['Static Analysis', '정적 보안 분석'],
  ['AI Analysis', 'AI 위험 분석'],
  ['Sandbox Check', '격리 환경 검사'],
  ['Validator Review', '검증자 판정'],
  ['Final Decision', '최종 실행 결정'],
]

export const isTarget = (value: unknown): value is Target => value === '1.0.0' || value === '1.0.1'
export const releaseIdOf = (target: Target) => `mail-mcp@${target}`
export const short = (sessionId: string) => sessionId.slice(0, 8).toUpperCase()
export const clock = (iso: string) => new Date(iso).toLocaleTimeString('en-GB', { hour12: false })
export const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds))

export function ago(iso: string) {
  const seconds = Math.max(0, (Date.now() - Date.parse(iso)) / 1000)
  if (seconds < 60) return '방금 전'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}분 전`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}시간 전`
  return new Date(iso).toLocaleDateString('ko-KR')
}

export class ScanApiError extends Error {
  constructor(message: string, readonly status: number) { super(message) }
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/judge/${path}`, { ...init, headers: init?.body ? { 'content-type': 'application/json' } : undefined, cache: 'no-store' })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}))
    throw new ScanApiError(payload?.error?.message ?? payload?.error ?? `HTTP ${response.status}`, response.status)
  }
  return response.json()
}

export const createSession = () => api<DemoSession>('sessions', { method: 'POST' })
export const getSession = (sessionId: string) => api<DemoSession>(`sessions/${sessionId}`)
export const runAction = (sessionId: string, action: string) => api<DemoSession>(`sessions/${sessionId}/actions`, { method: 'POST', body: JSON.stringify({ action }) })

export function errorText(cause: unknown) {
  if (cause instanceof ScanApiError && cause.status === 503) return '검사 백엔드에 연결할 수 없습니다. API 서버가 실행 중인지 확인해 주세요.'
  if (cause instanceof ScanApiError && cause.status === 404) return '검사 세션이 만료되었거나 찾을 수 없습니다. 새 검사를 시작해 주세요.'
  return cause instanceof Error ? cause.message : '검사 요청이 실패했습니다.'
}

const HISTORY_KEY = 'mcpshield-scan-history'

export function loadHistory(): ScanRecord[] {
  try {
    const records = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]')
    return Array.isArray(records) ? records : []
  } catch { return [] }
}

export function saveRecord(record: ScanRecord) {
  try {
    const rest = loadHistory().filter((item) => item.sessionId !== record.sessionId)
    localStorage.setItem(HISTORY_KEY, JSON.stringify([record, ...rest].slice(0, 20)))
  } catch {}
}

export const findRecord = (sessionId: string) => loadHistory().find((item) => item.sessionId === sessionId)

export function statusOf(session: DemoSession, target: Target): ScanStatus {
  const execution = session.executions.find((item) => item.releaseId === releaseIdOf(target))
  return execution ? (execution.decision === 'BLOCK' ? 'BLOCKED' : 'ALLOWED') : 'RUNNING'
}

// For a session found only on the backend (e.g. opened in another browser).
export function recordFromSession(session: DemoSession): ScanRecord {
  const target: Target = session.step > PLAN['1.0.0'].total ? '1.0.1' : '1.0.0'
  return { sessionId: session.sessionId, target, status: statusOf(session, target), startedAt: session.createdAt, updatedAt: new Date().toISOString(), baselineFindingCount: null, session }
}

export type StageStatus = 'pending' | 'running' | 'complete' | 'failed'

export function stageStatuses(step: number, target: Target, failed: boolean): StageStatus[] {
  const plan = PLAN[target]
  const span = (start: number, end: number): StageStatus => step > end ? 'complete' : step >= start ? 'running' : 'pending'
  const statuses = [span(0, plan.scan), span(plan.scan, plan.scan), span(plan.scan, plan.scan), span(plan.scan, plan.scan), span(plan.votes[0], plan.votes[1]), span(plan.run, plan.run)]
  return failed ? statuses.map((status) => status === 'running' ? 'failed' : status) : statuses
}

const severityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
export const severityClass = (severity: string) => severityRank[severity] >= 3 ? 'high' : severity === 'MEDIUM' ? 'medium' : 'low'
export const stageName = (stage: string) => ({ STATIC: 'Static Analysis', AI: 'AI Analysis', SANDBOX: 'Sandbox Check' } as Record<string, string>)[stage] ?? stage

export function reportOf(record: ScanRecord) {
  const { session, target } = record
  const releaseId = releaseIdOf(target)
  const findings = (target === '1.0.1' ? session.findings.slice(record.baselineFindingCount ?? 0) : session.findings)
    .slice().sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0))
  const votes = session.votes.filter((item) => item.releaseId === releaseId)
  const execution = session.executions.find((item) => item.releaseId === releaseId)
  const release = session.releases.find((item) => item.releaseId === releaseId)
  const severity = findings[0]?.severity ?? 'NONE'
  const failVotes = votes.filter((item) => item.decision === 'FAIL').length
  const stages = stageStatuses(session.step, target, record.status === 'FAILED')
  const byStage = (stage: string) => findings.filter((item) => item.stage === stage)
  return { releaseId, findings, votes, failVotes, execution, release, severity, stages, byStage, severityLevel: severityRank[severity] ?? 0 }
}
