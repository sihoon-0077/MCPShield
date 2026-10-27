// Korean renderings of the fixed texts the backend sends (scanner findings, judge session events,
// overview evidence). Codes such as CANARY_EXFILTRATION stay in English; EN always shows the backend
// original, and any text not listed here falls back to it in KR as well.
import type { Language } from './i18n'

const korean: Record<string, string> = {
  // services/scanner finding messages
  'An independent synthetic sink/proxy or full MCP surface comparison observed a restricted-profile violation.': '독립된 합성 sink·프록시 또는 전체 MCP 표면 비교에서 제한 프로필 위반이 관찰되었습니다.',
  'Artifact module loading or runtime egress is outside the self-contained Gateway profile.': '아티팩트의 모듈 로딩 또는 실행 중 외부 통신이 자체 완결형 Gateway 프로필을 벗어납니다.',
  'Fixture contains network egress while declaring no egress.': '외부 통신이 없다고 선언했지만 코드에 네트워크 외부 통신이 있습니다.',
  'Fixture reads a sensitive or injected canary file.': '민감 파일 또는 주입된 canary 파일을 읽는 코드가 있습니다.',
  'Install-time execution requires an isolated dependency installation profile.': '설치 시점에 실행되는 코드가 있어 격리된 의존성 설치 프로필이 필요합니다.',
  'Installed source contains a sensitive-file reference requiring semantic review.': '설치된 소스에 민감 파일 참조가 있어 의미 분석 검토가 필요합니다.',
  'Local semantic fallback found behavior that exceeds the declared MCP capability.': '로컬 의미 분석이 선언된 MCP 기능을 넘어서는 동작을 발견했습니다.',
  'The complete runtime MCP tools/list differs from the pinned manifest.': '실행 중 확인한 전체 MCP tools/list가 고정된 매니페스트와 다릅니다.',
  'The controlled proxy denied an undeclared destination or port.': '통제된 프록시가 선언되지 않은 목적지 또는 포트로의 접근을 차단했습니다.',
  'The declared MCP tool surface changed from the baseline release.': '선언된 MCP 도구 표면이 기준 릴리스와 달라졌습니다.',
  'The fixture launched a child process during sandbox execution.': '샌드박스 실행 중 자식 프로세스를 실행했습니다.',
  'The fixture opened a network connection while declaring no egress.': '외부 통신이 없다고 선언했지만 실행 중 네트워크 연결을 열었습니다.',
  'The fixture read the injected sensitive canary file at runtime.': '실행 중에 주입된 민감 canary 파일을 읽었습니다.',
  'The fixture sent the injected dummy canary to the controlled local sink.': '주입된 더미 canary를 통제된 로컬 수집 서버(sink)로 전송했습니다.',
  'The isolated external OCI collector observed a synthetic scope violation.': '격리된 외부 OCI 수집기가 합성 범위 위반을 관찰했습니다.',
  'Tool metadata contains instructions, sensitive references, or hidden text requiring review.': '도구 메타데이터에 검토가 필요한 지시문, 민감 참조 또는 숨겨진 텍스트가 있습니다.',
  // Overview MOCK / REPLAY evidence (lib/demo-data.ts, scripts/demo/replay.json)
  'Tool surface changed; review required': '도구 표면 변경 · 검토 필요',
  'Tool surface delta recorded': '도구 표면 변경 기록',
  'Behavior differs from declared mail scope': '선언된 메일 범위와 다른 동작',
  'Declared behavior mismatch': '선언된 동작과 불일치',
  'Dummy canary reached the local sink': '더미 canary가 로컬 sink에 도달',
  'Dummy canary reached local sink': '더미 canary가 로컬 sink에 도달',
  'Fixture read /sandbox/canary.txt': 'fixture가 /sandbox/canary.txt를 읽음',
  'POST to local exfil sink': '로컬 유출 수집 서버로 POST 전송',
  'Dummy token matched by the sink': 'sink가 더미 토큰을 확인',
  'No current evidence is available': '현재 사용할 수 있는 증거가 없습니다',
}

// apps/api judge-demo event details; some carry a release ID, status or validator name.
const events: [RegExp, (match: RegExpMatchArray) => string][] = [
  [/^Isolated synthetic judge session created$/, () => '격리된 합성 검사 세션을 생성했습니다'],
  [/^(\S+) finished with (\S+)$/, (match) => `${match[1]} 스캔 완료 · ${match[2]}`],
  [/^(PASS|FAIL) signed by (.+)$/, (match) => `${match[2]}가 ${match[1]} 판정에 서명했습니다`],
  [/^2-of-3 (PASS|FAIL) changed the (safe|malicious) release to (\S+)$/, (match) => `2-of-3 ${match[1]} 정족수로 ${match[2] === 'safe' ? '기준' : '후보'} 릴리스가 ${match[3]} 상태가 되었습니다`],
  [/^Verified safe MCP tool executed in the restricted Gateway runtime$/, () => '검증된 안전 MCP 도구를 제한된 Gateway 런타임에서 실행했습니다'],
  [/^Signed candidate (\S+) selected$/, (match) => `서명된 업데이트 후보를 선택했습니다 · ${match[1]}`],
  [/^Revoked artifact was rejected before its entrypoint started$/, () => '폐기된 아티팩트를 entrypoint 시작 전에 차단했습니다'],
]

export const localize = (text: string, language: Language) => language === 'KR' ? korean[text] ?? text : text

export function localizeEvent(detail: string, language: Language) {
  if (language !== 'KR') return detail
  for (const [pattern, render] of events) {
    const match = detail.match(pattern)
    if (match) return render(match)
  }
  return detail
}
