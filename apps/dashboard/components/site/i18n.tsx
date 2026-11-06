'use client'

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

export type Language = 'KR' | 'EN'
const LanguageContext = createContext<{ language: Language; setLanguage: (language: Language) => void } | null>(null)

const pairs: [string, string][] = [
  ['Security Scan', '보안 검사'], ['Scan Results', '검사 결과'], ['Validation Logs', '검증 로그'], ['History', '검사 기록'], ['Settings', '설정'], ['Overview', '개요'],
  ['WORKSPACE', '워크스페이스'], ['MANAGE', '관리'], ['System Operational', '시스템 정상'],
  ['New Scan', '새 검사'], ['SECURITY WORKSPACE', '보안 워크스페이스'],
  ['Scan target', '검사 대상'], ['Scan progress', '검사 진행'], ['Result summary', '결과 요약'], ['DRAFT', '초안'], ['COMPLETE', '완료'],
  ['Register an MCP tool and check it for security risks.', '검사할 MCP 도구를 등록하고 위험 여부를 확인합니다.'],
  ['MCP TOOL NAME', 'MCP 도구 이름'], ['VERSION', '버전'], ['SOURCE / REPOSITORY', '소스 / 저장소'], ['ARTIFACT HASH', '아티팩트 해시'], ['OPTIONAL', '선택'],
  ['TARGET TYPE', '대상 유형'], ['SCAN POLICY', '검사 정책'], ['ESTIMATED TIME', '예상 시간'], ['Remote repository', '원격 저장소'],
  ['Start Security Scan', '보안 검사 시작'], ['CURRENT TOOL', '현재 도구'], ['RISK LEVEL', '위험 수준'],
  ['Verification progress', '검증 진행'], ['Input analysis', '입력 분석'], ['Permission check', '권한 검사'], ['Issue found', '문제 발견'],
  ['Validator agreement', '검증자 합의'], ['DETECTED SECURITY ISSUE', '탐지된 보안 문제'], ['EXECUTION DECISION', '실행 결정'],
  ['ACTIVITY TIMELINE', '활동 타임라인'], ['Recent scans', '최근 검사'], ['Latest activity in this workspace', '이 워크스페이스의 최근 활동'],
  ['View all history', '전체 기록 보기'], ['TOOL', '도구'], ['STATUS', '상태'], ['RISK', '위험도'], ['TIME', '시간'],
  ['Blocked', '차단됨'], ['Allowed', '허용됨'], ['Review', '검토'], ['High', '높음'], ['Medium', '중간'], ['Low', '낮음'],
  ['LIVE SECURITY ANALYSIS', '실시간 보안 분석'], ['Back to Scan', '검사 화면으로 돌아가기'],
  ['MCP TOOL', 'MCP 도구'], ['SCAN ID', '검사 ID'], ['STAGE-BASED PROGRESS', '단계 기반 진행'], ['stages', '단계'],
  ['Artifact Fetch', '아티팩트 수집'], ['Static Analysis', '정적 분석'], ['Sandbox Check', '샌드박스 검사'], ['Validator Review', '검증자 검토'], ['Final Decision', '최종 결정'],
  ['IN PROGRESS', '진행 중'], ['PENDING', '대기'], ['DONE', '완료'], ['FAILED', '실패'], ['COMPLETED', '완료됨'], ['WAITING', '대기 중'], ['SCANNING', '검사 중'], ['INITIALIZING', '초기화 중'],
  ['Retry', '다시 시도'], ['View Scan Results', '검사 결과 확인하기'],
  ['CURRENT ANALYSIS', '현재 분석'], ['CURRENT TASK', '현재 작업'], ['PACKAGE', '패키지'], ['POLICY', '정책'], ['ENVIRONMENT', '환경'],
  ['Manifest inspection', '매니페스트 검사'], ['Permission mapping', '권한 매핑'], ['Behavior analysis', '동작 분석'], ['SECURITY EVENTS', '보안 이벤트'], ['Analysis activity', '분석 활동'], ['events', '이벤트'],
  ['Package metadata retrieved', '패키지 메타데이터 수집'], ['Artifact integrity checked', '아티팩트 무결성 확인'], ['Static analysis completed', '정적 분석 완료'], ['Validator review requested', '검증자 검토 요청'],
  ['INVESTIGATION REPORT', '조사 보고서'], ['Export Report', '보고서 내보내기'], ['Re-run Scan', '다시 검사'], ['Scan complete', '검사 완료'],
  ['FINAL VERDICT', '최종 판정'], ['BLOCKED', '차단됨'], ['Execution prevented', '실행이 차단되었습니다'], ['RISK SCORE', '위험 점수'], ['ISSUES DETECTED', '탐지된 문제'], ['findings', '건'],
  ['VALIDATOR AGREEMENT', '검증자 합의'], ['unsafe', '위험 판정'], ['ANALYSIS FLOW', '분석 흐름'], ['Security investigation map', '보안 조사 맵'],
  ['Package secured', '패키지 확보'], ['Anomaly identified', '이상 징후 식별'], ['Outbound call detected', '외부 호출 감지'], ['Execution blocked', '실행 차단'],
  ['BEHAVIOR SIGNAL', '동작 신호'], ['POLICY ENGINE', '정책 엔진'],
  ['Enforcement: block', '적용: 차단'], ['Verified', '검증됨'], ['Review', '검토'], ['Risk detected', '위험 감지'], ['SCAN SUBJECT', '검사 대상'], ['Result details', '결과 상세'],
  ['HIGH RISK', '높은 위험'], ['Repository', '저장소'], ['Severity', '심각도'], ['Validator notes', '검증자 메모'], ['PRIMARY REASON', '주요 사유'], ['Detected during Sandbox Check', '샌드박스 검사 중 탐지'],
  ['FINAL EXECUTION DECISION', '최종 실행 결정'], ['Policy engine prevented tool execution.', '정책 엔진이 도구 실행을 차단했습니다.'], ['DETECTED ISSUES', '탐지된 문제'], ['Findings', '탐지 결과'], ['total', '전체'],
  ['TRACE EVIDENCE', '추적 증거'], ['Evidence & logs', '증거 및 로그'], ['View raw validation logs', '원본 검증 로그 보기'],
  ['SCAN ARCHIVE', '검사 아카이브'], ['Scan history', '검사 기록'], ['Completed and interrupted security scans', '완료되거나 중단된 보안 검사'],
  ['Start First Scan', '첫 검사 시작하기'],
  ['Security scan in progress.', '보안 검사를 진행하고 있습니다.'], ['Analyzing AI tool risks and validating the results.', 'AI 도구의 위험 요소를 분석하고 검증 결과를 확인하고 있습니다.'],
  ['Preparing the scan environment.', '검사 환경을 준비하고 있습니다.'], ['Checking tool information and analysis policies.', '도구 정보와 분석 정책을 확인하는 중입니다.'],
  ['Comparing declared capabilities with actual behavior patterns.', '도구의 선언된 기능과 실제 동작 패턴을 비교하고 있습니다.'],
  ['Waiting for Validator Review', '검증자 판정 대기'], ['Waiting for independent validator analysis.', '독립 검증자의 분석 결과를 기다리고 있습니다.'],
  ['Scan completed.', '검사가 완료되었습니다.'], ['All analysis stages and validator reviews are complete.', '모든 분석 단계와 검증자 판정이 완료되었습니다.'],
  ['Unable to complete scan.', '검사를 완료하지 못했습니다.'], ['Unable to connect to the analysis environment. Please try again.', '분석 환경에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.'],
  ['No scan history has been saved yet.', '아직 저장된 검사 기록이 없습니다.'], ['Complete a security scan to view its result here.', '보안 검사를 완료하면 이곳에서 결과 기록을 확인할 수 있습니다.'],
  ['Security scan history for this workspace.', '이 워크스페이스에서 실행한 보안 검사 기록입니다.'],
  ['Preparing session…', '세션 준비 중…'],
  ['Results appear once a scan completes.', '검사를 시작하면 결과가 표시됩니다.'],
  ['Blocked safely before execution.', '실행 전에 안전하게 차단되었습니다.'],
  ['No completed scans yet.', '아직 완료된 검사가 없습니다.'],
  ['Verifying the baseline release first.', '기준 버전을 먼저 검증하고 있습니다.'],
  ['Security scan complete.', '보안 검사가 완료되었습니다.'],
  ['Scan in progress…', '검사 진행 중…'],
  ['Start new scan', '새 검사 시작'],
  ['All stages complete', '모든 단계 완료'],
  ['No scan in progress.', '진행 중인 검사가 없습니다.'],
  ['Start a new scan from the Security Scan screen.', '보안 검사 화면에서 새 검사를 시작해 주세요.'],
  ['Awaiting votes', '판정 대기'],
  ['Execution approved', '실행 승인'],
  ['No security issues detected.', '탐지된 보안 문제가 없습니다.'],
  ['Loading scan results.', '검사 결과를 불러오는 중입니다.'],
  ['No scan results to show.', '표시할 검사 결과가 없습니다.'],
  ['Complete a security scan to see the result here.', '보안 검사를 완료하면 이곳에서 결과를 확인할 수 있습니다.'],
  ['Security scans run in this browser.', '이 브라우저에서 실행한 보안 검사 기록입니다.'],
  ['Loading scan history.', '검사 기록을 불러오는 중입니다.'],
  ['Running', '실행 중'],
  ['Failed', '중단됨'],
  ['No findings', '탐지 없음'],
  ['Digest & tool surface computed', '다이제스트 · 도구 표면 계산'],
  ['Digest computed', '다이제스트 계산'],
  ['No suspicious behavior detected', '의심 동작 없음'],
  ['validators approved', '검증자 승인'],
  ['validators recommend blocking', '검증자가 차단 권고'],
  ['View full scan report', '전체 보고서 보기'],
  ['HIGHEST SEVERITY', '최고 심각도'],
  ['RELEASE REGISTRY', '릴리스 레지스트리'],
  ['Not run', '미실행'],
  ['Interrupted', '중단'],
  ['No anomalous behavior', '이상 동작 없음'],
  ['All checks passed', '모든 검사 통과'],
  ['All analysis stages passed', '모든 분석 단계 통과'],
  ['In progress', '분석 중'],
  ['1.0.1 · candidate', '1.0.1 · 후보'], ['1.0.0 · baseline', '1.0.0 · 기준'], ['Operations console', '운영 콘솔'],
  ['Fetching the artifact.', '아티팩트를 수집하고 있습니다.'],
  ['Fetching the package and computing its artifact digest and tool surface.', '패키지를 가져와 artifact digest와 tool surface를 계산합니다.'],
  ['Running static analysis.', '정적 분석을 진행하고 있습니다.'],
  ['Looking for sensitive file reads, undeclared network access and tool surface changes in the code.', '민감 파일 접근 · 선언되지 않은 네트워크 · 도구 표면 변경을 코드에서 찾습니다.'],
  ['Running the sandbox check.', '샌드박스 검사를 진행하고 있습니다.'],
  ['Running it in isolation to watch for canary leaks and outbound connections.', '격리 환경에서 실행해 canary 유출과 외부 연결을 관찰합니다.'],
  ['The Gateway allows or blocks execution based on the verification result.', 'Gateway가 검증 결과로 실행 허용 또는 차단을 결정합니다.'],
]

const enToKo = new Map(pairs)
const koToEn = new Map(pairs.map(([en, ko]) => [ko, en]))
// Panel eyebrows stay English in both languages (each sits above a Korean title); the server renders them as they are shown.
const bilingualTechnicalLabels = new Set([
  'SECURITY WORKSPACE', 'INVESTIGATION REPORT', 'SCAN ARCHIVE', 'RELEASE REGISTRY', 'RELEASE HISTORY',
  'FINAL VERDICT', 'RISK SCORE', 'ISSUES DETECTED', 'VALIDATOR AGREEMENT',
  'ANALYSIS FLOW', 'BLOCKED',
  'SCAN SUBJECT', 'DETECTED ISSUES', 'TRACE EVIDENCE', 'Evidence & logs',
  'LIVE SECURITY ANALYSIS', 'CURRENT ANALYSIS', 'SECURITY EVENTS',
])

function translateText(text: string, language: Language) {
  const trimmed = text.trim()
  if (!trimmed) return text
  if (language === 'KR' && bilingualTechnicalLabels.has(trimmed)) return text
  const translated = (language === 'KR' ? enToKo : koToEn).get(trimmed)
  if (!translated) return text
  return text.replace(trimmed, translated)
}

function translateWorkspace(language: Language) {
  const root = document.querySelector('.workspace')
  if (!root) return
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
  let node = walker.nextNode()
  while (node) {
    const element = node.parentElement
    if (element && !element.closest('.mono, .log-list, code, pre, [data-raw]')) {
      const current = node.textContent || ''
      const translated = translateText(current, language)
      if (translated !== current) node.textContent = translated
    }
    node = walker.nextNode()
  }
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>('KR')
  useEffect(() => {
    if (localStorage.getItem('mcpshield-language') === 'EN') setLanguageState('EN')
  }, [])
  const setLanguage = (next: Language) => {
    localStorage.setItem('mcpshield-language', next)
    setLanguageState(next)
  }
  useEffect(() => {
    translateWorkspace(language)
    const observer = new MutationObserver(() => translateWorkspace(language))
    observer.observe(document.body, { childList: true, subtree: true, characterData: true })
    return () => observer.disconnect()
  }, [language])
  return <LanguageContext.Provider value={{ language, setLanguage }}>{children}</LanguageContext.Provider>
}

export function useLanguage(): Language {
  return useContext(LanguageContext)?.language ?? 'KR'
}

export function LanguageSwitcher() {
  const context = useContext(LanguageContext)
  if (!context) return null
  return <div className="language-switcher" role="group" aria-label="Language">
    {(['KR', 'EN'] as Language[]).map((language) => <button className={context.language === language ? 'active' : ''} onClick={() => context.setLanguage(language)} key={language}>{language}</button>)}
  </div>
}
