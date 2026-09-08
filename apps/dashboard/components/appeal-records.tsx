import React, { useState, type FormEvent } from "react";
import { controlApi } from "../lib/control-client";
import { SemanticEvidenceNotice, type Release, type Scan } from "./release-workflow";
import { ScanRequestForm, type ScanPolicy } from "./scan-request-form";

export type Appeal = { appealId: string; releaseId: string; reason: string; status: string; createdAt: string; scanId?: string | null; resolution?: string; resolvedAt?: string;
  original?: { artifactDigest: string; policyHash: string | null; reportRoot: string | null }; rescan?: null | { scanId: string; releaseId: string; policyHash: string; requestedAt: string } };
const date = (value?: string) => value ? new Date(value).toLocaleString("ko-KR") : "API 기록 없음";
const originalText = { whiteSpace: "pre-wrap" as const, overflowWrap: "anywhere" as const };
export const linkedAppealScan = (appeal: Appeal, scan?: Scan) => Boolean(appeal.rescan && scan && scan.scanId === appeal.rescan.scanId && scan.appealId === appeal.appealId && scan.releaseId === appeal.rescan.releaseId && scan.policyHash === appeal.rescan.policyHash);

function AppealRescan({ appeal, scans, releases, policies, operator, busy, onRefresh, onSelect }: { appeal: Appeal; scans: Scan[]; releases: Release[]; policies: ScanPolicy[]; operator: boolean; busy: boolean; onRefresh?: () => Promise<void>; onSelect?: (id: string) => void }) {
  // A manual lookup handles linked jobs outside the 250-item inventory. Any new
  // inventory (including refresh failure) invalidates that earlier lookup.
  const [lookup, setLookup] = useState<{ inventory: Scan[]; scan?: Scan; error?: string } | null>(null), [pending, setPending] = useState(false);
  const current = lookup?.inventory === scans ? lookup : null;
  const candidate = current ? current.scan : scans.find(scan => scan.scanId === appeal.rescan?.scanId);
  const scan = linkedAppealScan(appeal, candidate) ? candidate : undefined;
  const original = releases.find(release => release.releaseId === appeal.releaseId);
  return <section aria-label={`이의제기 ${appeal.appealId} 재검사 연결`}>
    <h4>접수 당시 증거 · 변경하지 않는 원본</h4>
    <dl className="ops-facts">{[["원본 릴리스 ID", appeal.releaseId], ["원본 artifact digest", appeal.original?.artifactDigest], ["원본 정책", appeal.original?.policyHash], ["원본 증거 루트", appeal.original?.reportRoot]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? "접수 시 기록 없음"}</dd></div>)}</dl>
    <h4>연결된 새 검사 · 원본과 별도</h4>
    {appeal.rescan ? <>
      <dl className="ops-facts">{[["새 검사 ID", appeal.rescan.scanId], ["검사 대상 릴리스 ID", appeal.rescan.releaseId], ["새 검사 정책", appeal.rescan.policyHash], ["요청 일시", date(appeal.rescan.requestedAt)]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      {scan ? <><p><b>{scan.status}</b> · {scan.status === "QUEUED" ? "검사 대기 중" : scan.status === "RUNNING" ? "검사 진행 중" : scan.status === "DEAD_LETTER" ? "검사 처리 실패 · 검사 작업에서 원인과 재처리 가능 여부 확인" : scan.status === "COMPLETED" ? "검사 작업 완료 · 실행 승인 아님" : "알 수 없는 작업 상태"}<br />단계 {scan.stage} · 시도 {scan.attempts}/{scan.maxAttempts} · 마지막 API 기록 {date(scan.updatedAt)}</p>
        {scan.status === "COMPLETED" && <><p>새 결과 상태: {scan.result?.state ?? "미제공"} · 권고: {scan.result?.verdict ?? "미제공"} · 분석: {scan.result?.scanResult?.scanStatus ?? "미제공"}<br />새 증거 루트: <code>{scan.result?.reportRoot ?? "미제공"}</code></p><SemanticEvidenceNotice evidence={scan.result} /></>}
      </> : <p className="ops-empty">현재 검사 상태 미확인 · 연결 식별자와 일치하는 결과를 조회해야 합니다. 누락을 완료나 승인으로 간주하지 않습니다.</p>}
      {current?.error && <p className="ops-message error" role="alert">{current.error}</p>}
      <button type="button" disabled={busy || pending} onClick={() => {
        if (pending) return; setPending(true); setLookup({ inventory: scans });
        void controlApi<{ scan: Scan }>(`scans/${encodeURIComponent(appeal.rescan!.scanId)}`).then(result => {
          if (!linkedAppealScan(appeal, result.scan)) throw new Error("이의제기와 검사 식별자가 일치하지 않습니다.");
          setLookup({ inventory: scans, scan: result.scan });
        }).catch(() => setLookup({ inventory: scans, error: "연결된 검사 조회 실패 · 이전 조회 결과는 숨겼습니다. 새로고침 후 다시 확인하세요." })).finally(() => setPending(false));
      }}>연결된 검사 현재 결과 조회</button>
      {onSelect && <button type="button" disabled={busy || pending} onClick={() => onSelect(appeal.rescan!.releaseId)}>대상 릴리스의 검증·실행 판정 보기</button>}
      <p className="ops-data-note">새 검사 연결은 1회만 가능합니다. 변경 이력의 appeal.rescan.queued / completed / failed를 확인하세요. 종결 여부와 재검사 결과는 별도이며 검증자·체인·Gateway 실행 판정을 바꾸지 않습니다.</p>
    </> : <>
      <p className="ops-empty">아직 연결된 새 검사가 없습니다.</p>
      {operator && appeal.status === "OPEN" && onRefresh && original && appeal.original?.artifactDigest ? <ScanRequestForm releases={releases} policies={policies} appeal={{ appealId: appeal.appealId, toolId: original.toolId, artifactDigest: appeal.original.artifactDigest, policyHash: appeal.original.policyHash }} disabled={busy} onRefresh={onRefresh} />
        : <p className="ops-data-note">새 검사 요청에는 operator/admin 권한, OPEN 상태와 원본 식별 기록이 필요합니다. reader는 기록만 조회합니다. 원본이 목록에 없다면 인벤토리를 새로고침하세요.</p>}
    </>}
  </section>;
}

export function AppealRecords({ appeals, manage, busy = false, onResolve, releases = [], policies = [], scans = [], operator = false, onRefresh, onSelect }: { appeals: Appeal[]; manage: boolean; busy?: boolean; onResolve?: (event: FormEvent<HTMLFormElement>, appeal: Appeal) => void; releases?: Release[]; policies?: ScanPolicy[]; scans?: Scan[]; operator?: boolean; onRefresh?: () => Promise<void>; onSelect?: (id: string) => void }) {
  return <div aria-label="이의제기 검토 및 종결 기록">
    <p className="ops-data-note">이의제기 종결은 실행 승인이 아닙니다. 기존 REVOKED·QUARANTINED 상태나 검증자 판정을 바꾸지 않으며, 새 검사·검증·Gateway 실행 판정은 별도로 확인합니다.</p>
    {!appeals.length && <p className="ops-empty">불러온 이의제기가 없습니다.</p>}
    {appeals.map(appeal => <article className="ops-appeal" key={appeal.appealId} aria-label={`이의제기 ${appeal.appealId}`}>
      <b>{appeal.status}</b><small> · 접수 {date(appeal.createdAt)}</small>
      <p><code>{appeal.appealId}</code></p><h4>접수된 이유 · 원문</h4><p style={originalText}>{appeal.reason}</p>
      {appeal.scanId && <p>접수 시 참조한 검사 ID: <code>{appeal.scanId}</code></p>}
      <AppealRescan appeal={appeal} scans={scans} releases={releases} policies={policies} operator={operator} busy={busy} onRefresh={onRefresh} onSelect={onSelect} />
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
