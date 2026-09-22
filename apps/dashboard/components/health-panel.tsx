import React, { useEffect, useRef, useState } from "react";
import { controlApi } from "../lib/control-client";
import { healthComponents, type HealthComponent, type ControlHealth } from "../lib/control-health";

const names = { api: "API · 요청 처리", database: "DB · 기록 저장", chain: "체인 · 검증 기록", scanner: "스캐너 · 검사 실행" };
const statuses: Record<HealthComponent["status"], string> = { UP: "응답 확인", DOWN: "연결 실패", UNKNOWN: "상태 미확인", NOT_CONFIGURED: "연동 미설정", LIMITED: "확인 범위 제한" };
type State = { report: ControlHealth | null; pending: boolean; error: string };

export function HealthStatus({ report, pending, error }: State) {
  // Neither an in-flight check nor a failed check may render an earlier READY snapshot.
  const current = pending || error ? null : report;
  return <div aria-live="polite" aria-busy={pending}>
    {error ? <p className="ops-message error" role="alert">{error}</p> : pending ? <p className="ops-data-note">연결 상태를 확인하고 있습니다. 이전 정상 표시는 숨겼습니다.</p> : !current ? <p className="ops-empty">종합 상태 미확인</p> : <>
      <p><b>{current.status === "READY" ? "필수 구성요소 응답 확인" : "추가 확인이 필요한 구성요소가 있습니다"}</b> · <code>{current.status}</code></p>
      <p className="ops-data-note">API 보고 시각: <time dateTime={current.checkedAt}>{new Date(current.checkedAt).toLocaleString("ko-KR")}</time> · 현재 표시값은 마지막 조회 기록입니다.</p>
      <div className="ops-table-wrap"><table><thead><tr><th>구성요소</th><th>확인 결과</th><th>사유 코드</th><th>구성요소 확인 시각</th></tr></thead><tbody>{healthComponents.map(name => {
        const component = current.components[name];
        return <tr key={name}><td>{names[name]}</td><td><b>{statuses[component.status]}</b><small>{component.status}</small></td><td><code>{component.code}</code></td><td>{component.checkedAt ? <time dateTime={component.checkedAt}>{new Date(component.checkedAt).toLocaleString("ko-KR")}</time> : "실제 확인 기록 없음"}</td></tr>;
      })}</tbody></table></div>
    </>}
    <p className="ops-data-note">서비스 연결 상태는 릴리스 안전성이나 실행 승인이 아닙니다. 체인 응답만으로 최종성·검증자 합의가 보장되지 않으며, 스캐너 연결만으로 모든 검사·외부 AI의 탐지 품질이 검증되는 것은 아닙니다.</p>
  </div>;
}

export function HealthPanel({ refreshVersion }: { refreshVersion: number }) {
  const [state, setState] = useState<State>({ report: null, pending: false, error: "" }), [hint, setHint] = useState("");
  const active = useRef<AbortController | null>(null), lastStarted = useRef(0);
  function refresh(manual = false) {
    if (active.current || document.hidden) return;
    if (Date.now() - lastStarted.current < 15000) { if (manual) setHint("상태 조회는 15초에 한 번 가능합니다. 잠시 후 다시 확인하세요."); return; }
    lastStarted.current = Date.now(); const controller = new AbortController(); active.current = controller;
    const timer = setTimeout(() => controller.abort(), 12000);
    setHint(""); setState({ report: null, pending: true, error: "" });
    void controlApi<ControlHealth>("health", undefined, "GET", undefined, controller.signal).then(report => {
      if (active.current === controller) setState({ report, pending: false, error: "" });
    }).catch((error: { status?: number }) => {
      if (active.current === controller) setState({ report: null, pending: false, error: error.status === 401 ? "운영 로그인이 만료되었습니다. 다시 연결한 후 상태를 확인하세요." : "종합 상태를 확인하지 못했습니다. 이전 정상 표시는 숨겼습니다. 연결 상태를 다시 확인하세요." });
    }).finally(() => { clearTimeout(timer); if (active.current === controller) active.current = null; });
  }
  useEffect(() => { refresh(); }, [refreshVersion]);
  useEffect(() => {
    const visible = () => { if (!document.hidden) refresh(); };
    document.addEventListener("visibilitychange", visible);
    return () => { document.removeEventListener("visibilitychange", visible); active.current?.abort(); active.current = null; lastStarted.current = 0; };
  }, []);
  return <section className="ops-panel" aria-label="서비스 종합 연결 상태">
    <div className="ops-section-heading"><h2>서비스 연결 상태</h2><button type="button" disabled={state.pending} onClick={() => refresh(true)}>연결 상태 다시 확인</button></div>
    <p className="ops-data-note">로그인·목록 새로고침 시 별도로 조회합니다. 최대 15초에 한 번 조회하며 숨겨진 탭에서는 새 조회를 시작하지 않습니다. 이 조회 실패만으로 릴리스 목록을 지우지 않습니다.</p>
    {hint && <p className="ops-data-note" role="status">{hint}</p>}
    <HealthStatus {...state} />
  </section>;
}
