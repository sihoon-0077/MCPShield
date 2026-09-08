import React, { type FormEvent } from "react";

export type Appeal = { appealId: string; releaseId: string; reason: string; status: string; createdAt: string; scanId?: string | null; resolution?: string; resolvedAt?: string };
const date = (value?: string) => value ? new Date(value).toLocaleString("ko-KR") : "API 기록 없음";
const originalText = { whiteSpace: "pre-wrap" as const, overflowWrap: "anywhere" as const };

export function AppealRecords({ appeals, manage, busy = false, onResolve }: { appeals: Appeal[]; manage: boolean; busy?: boolean; onResolve?: (event: FormEvent<HTMLFormElement>, appeal: Appeal) => void }) {
  return <div aria-label="이의제기 검토 및 종결 기록">
    <p className="ops-data-note">이의제기 종결은 실행 승인이 아닙니다. 기존 REVOKED·QUARANTINED 상태나 검증자 판정을 바꾸지 않으며, 새 검사·검증·Gateway 실행 판정은 별도로 확인합니다.</p>
    {!appeals.length && <p className="ops-empty">불러온 이의제기가 없습니다.</p>}
    {appeals.map(appeal => <article className="ops-appeal" key={appeal.appealId} aria-label={`이의제기 ${appeal.appealId}`}>
      <b>{appeal.status}</b><small> · 접수 {date(appeal.createdAt)}</small>
      <p><code>{appeal.appealId}</code></p><h4>접수된 이유 · 원문</h4><p style={originalText}>{appeal.reason}</p>
      {appeal.scanId && <p>접수 시 참조한 검사 ID: <code>{appeal.scanId}</code></p>}
      {appeal.status === "RESOLVED" && <><h4>관리자 검토 결론 · API 기록</h4><p style={originalText}>{appeal.resolution ?? "결론 미제공"}</p><p>종결 일시: <time dateTime={appeal.resolvedAt}>{date(appeal.resolvedAt)}</time></p><small>종결된 기록을 이 화면에서 다시 덮어쓰지 않습니다. 변경 이력에서 appeal.resolved 이벤트를 확인하세요.</small></>}
      {manage && appeal.status === "OPEN" && <form method="post" aria-label={`이의제기 ${appeal.appealId} 종결`} onSubmit={event => { event.preventDefault(); onResolve?.(event, appeal); }}>
        <p id={`appeal-help-${appeal.appealId}`} className="ops-data-note">관리자만 결론을 기록할 수 있습니다. 재현 조건·판단 근거를 적되 개인정보·API 키·비밀값은 넣지 마세요. 응답이 불확실하면 먼저 목록을 새로고침하여 기존 종결 기록을 확인하세요.</p>
        <label>관리자 검토 결론<textarea name="resolution" required minLength={8} maxLength={2000} rows={4} disabled={busy} aria-describedby={`appeal-help-${appeal.appealId}`} autoComplete="off" /></label>
        <label className="ops-check"><input type="checkbox" required disabled={busy} />이 결론은 검토 종결이며 릴리스 실행 허용이나 폐기 해제가 아님을 확인했습니다.</label>
        <button disabled={busy}>검토 결론 기록 · 이의제기 종결</button>
      </form>}
      {!manage && appeal.status === "OPEN" && <p className="ops-data-note">reader/operator는 결론을 작성할 수 없습니다. 관리자 검토 대기 중입니다.</p>}
    </article>)}
  </div>;
}
