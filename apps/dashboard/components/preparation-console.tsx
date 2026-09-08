"use client";

import React, { useEffect, useRef, useState, type FormEvent } from "react";
import { controlApi } from "../lib/control-client";
import type { ReceiptEvidenceSummary } from "../lib/receipt-summary";
import type { Release } from "./release-workflow";

export type Preparation = { preparationId: string; sourceReleaseId: string; policyHash: string; status: string; attempts: number; maxAttempts: number; traceId: string; createdAt: string; updatedAt: string;
  lastError?: { code: string; retryable: boolean }; result?: { outcome: string; verdict: string; releaseId?: string; scanId?: string; reportRoot: string; issues: string[] } };
export type PreparationPolicy = { policyHash: string; alias: string; version?: string; deprecatedAt: string | null; document: unknown };
const short = (value?: string) => value ? `${value.slice(0, 12)}…${value.slice(-8)}` : "없음";
const date = (value: string) => new Date(value).toLocaleString("ko-KR");
export const canPrepare = (release: Release) => ["npm", "tarball"].includes(release.sourceType ?? "") && !release.runtimeProfile;
export const canRetryPreparation = (job: Preparation) => job.status === "DEAD_LETTER" && job.lastError?.retryable === true;
export const isPreparationPolicy = (policy: PreparationPolicy) => !policy.deprecatedAt && (policy.document as { profile?: string })?.profile === "restricted-node-docker-v1";

export function PreparationRecords({ jobs, releases, operator, busy = false, onOpen, onRetry }: { jobs: Preparation[]; releases: Release[]; operator: boolean; busy?: boolean; onOpen?: (job: Preparation) => void; onRetry?: (job: Preparation) => void }) {
  return <div className="ops-table-wrap"><table><caption>최근 준비 작업 · 작업 완료와 보안 승인은 별도</caption><thead><tr><th>작업 / 원본</th><th>작업 상태</th><th>준비 결과</th><th>현재 실행 릴리스</th><th>조치</th></tr></thead><tbody>{jobs.map(job => {
    const derived = releases.find(release => release.releaseId === job.result?.releaseId);
    return <tr key={job.preparationId}><td><code title={job.preparationId}>{short(job.preparationId)}</code><small title={job.sourceReleaseId}>원본 {short(job.sourceReleaseId)}</small></td>
      <td><b>{job.status}</b><small>시도 {job.attempts} / {job.maxAttempts}</small><small>{date(job.updatedAt)}</small>{job.lastError && <small className="ops-flow-error">{job.lastError.code}</small>}</td>
      <td><b>{job.result?.outcome ?? "결과 없음"}</b><small>{job.result ? `권고 ${job.result.verdict}` : "대기·실행 중은 PASS가 아닙니다."}</small><small>{job.result?.outcome === "INCONCLUSIVE" ? "판단 근거 부족 · 실행 릴리스 생성 미확인" : "COMPLETED ≠ VERIFIED"}</small></td>
      <td>{job.result?.releaseId ? <><code title={job.result.releaseId}>{short(job.result.releaseId)}</code><small>{derived ? `현재 상태 ${derived.status}` : "현재 상태 미조회"}</small><small>원본과 다른 exact release ID</small></> : "아직 없음"}</td>
      <td className="ops-actions"><button disabled={busy} onClick={() => onOpen?.(job)}>작업 상세</button>{operator && canRetryPreparation(job) && <button disabled={busy} onClick={() => onRetry?.(job)}>실패 작업 재시도</button>}</td></tr>;
  })}</tbody></table>{!jobs.length && <p className="ops-empty">불러온 준비 작업이 없습니다. 실행 이미지 준비나 보안 승인이 완료된 상태가 아닙니다.</p>}</div>;
}

export function PreparationDetail({ job, operator, summary, onSelect, onEvidence }: { job: Preparation; operator: boolean; summary: ReceiptEvidenceSummary | null; onSelect?: (id: string) => void; onEvidence?: () => void }) {
  const result = job.result, verified = summary?.verification === "API_VERIFIED" && summary.root === result?.reportRoot;
  return <article className="ops-preparation-detail"><h3>원본 → 준비된 실행 릴리스</h3><dl className="ops-facts">{[["원본 exact release ID (불변)", job.sourceReleaseId], ["준비 결과 exact release ID", result?.releaseId], ["연결된 검사 ID", result?.scanId], ["적용 정책 해시", job.policyHash], ["증거 루트", result?.reportRoot], ["추적 ID", job.traceId]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? "생성되지 않음"}</dd></div>)}</dl>
    <p>원본 파일의 식별자는 유지됩니다. 준비된 이미지·실행 정책·도구 목록은 별도 릴리스로 검증하며, 등록 직후 상태는 UNVERIFIED입니다. 작업 COMPLETED나 구성 파일 다운로드는 실행 허가가 아닙니다.</p>
    {result?.issues?.length ? <p className="ops-data-note">남은 확인 항목: {result.issues.join(" · ")}</p> : null}
    <div className="ops-actions"><button onClick={() => onSelect?.(job.sourceReleaseId)}>원본 릴리스 보기</button>{result?.releaseId && <button onClick={() => onSelect?.(result.releaseId!)}>실행 릴리스의 검증 흐름 보기</button>}</div>
    {summary && <p className={verified ? "ops-message" : "ops-message error"} role={verified ? "status" : "alert"}>{verified ? `API가 증거 루트를 검증함 · 파일 ${summary.leafCount}개 · ${date(summary.checkedAt)}` : "증거 루트가 작업 결과와 다릅니다. 검증 완료로 표시하지 않습니다."}<br />브라우저 독립 검증이 아니며 원문 도구·파일·호출 인자는 화면에 전달하지 않습니다.</p>}
    {operator && result?.reportRoot && <button onClick={onEvidence}>API 증거 검증 요약 조회</button>}
    {operator && result?.releaseId && <div className="ops-chain-admin"><h3>운영자 · 로컬 Gateway 구성</h3><p>전체 도구 메타데이터를 포함한 비공개 JSON 파일입니다. 공유하지 말고 운영 호스트에 보관하세요. API 토큰·개인키 입력이나 브라우저 서명은 필요하지 않습니다.</p>
      <a className="ops-download" href={`/api/control/releases/${encodeURIComponent(result.releaseId)}/gateway-config`} download>Gateway 구성 JSON 다운로드</a>
      <p>Linux Docker 호스트에 같은 고정 이미지가 이미 있어야 합니다. 다운로드가 이미지를 복사·설치하거나 실행하지 않습니다.</p><pre>node apps/gateway/src/index.mjs stdio --prepared-identity /private/gateway.json</pre>
      <p>운영자가 별도로 설정한 V2 서명 검증 정보와 최신 실행 허가가 필요합니다. 검증자 서명은 외부 CLI에서 수행합니다.</p></div>}
    {!operator && <p className="ops-data-note">reader는 작업 메타데이터만 조회합니다. 준비 요청·재시도·증거 요약·구성 내보내기는 operator/admin 권한이 필요합니다.</p>}
  </article>;
}

export function PreparationConsole({ jobs, releases, policies, operator, onRefresh, onSelect }: { jobs: Preparation[]; releases: Release[]; policies: PreparationPolicy[]; operator: boolean; onRefresh: () => Promise<void>; onSelect: (id: string) => void }) {
  const [detail, setDetail] = useState<Preparation | null>(null), [summary, setSummary] = useState<ReceiptEvidenceSummary | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [message, setMessage] = useState("");
  const attempt = useRef<{ signature: string; key: string } | null>(null);
  useEffect(() => {
    if (!detail) return;
    const current = jobs.find(job => job.preparationId === detail.preparationId);
    if (!current || current.updatedAt !== detail.updatedAt) { setDetail(current ?? null); setSummary(null); }
  }, [jobs]);
  async function perform(work: () => Promise<void>) {
    setBusy(true); setError(""); setMessage(""); setSummary(null);
    try { await work(); } catch (error) { setDetail(null); setError(error instanceof Error ? error.message : "준비 작업 조회 실패"); }
    finally { setBusy(false); }
  }
  function prepare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget, data = new FormData(form);
    const sourceId = String(data.get("sourceId") ?? ""), policyHash = String(data.get("policyHash") ?? "");
    const signature = `${sourceId}:${policyHash}`;
    if (attempt.current?.signature !== signature) attempt.current = { signature, key: crypto.randomUUID() };
    const key = attempt.current.key;
    void perform(async () => {
      const { preparation } = await controlApi<{ preparation: Preparation }>(`releases/${encodeURIComponent(sourceId)}/prepare`, { policyHash }, "POST", key);
      await onRefresh(); attempt.current = null; form.reset(); setDetail(preparation);
      setMessage("준비 요청을 접수했습니다. 원본은 변경되지 않으며 작업·검사·체인 승인 상태를 각각 확인하세요.");
    });
  }
  return <section className="ops-panel ops-preparations" aria-label="npm 실행 이미지 준비">
    <div className="ops-section-heading"><h2>npm 실행 이미지 준비</h2><span className="ops-badge">V2 운영 API · 승인과 별도</span></div>
    <p>원본 등록 → 고정 이미지 준비 → 별도 릴리스 검사 → 검증자·체인 승인 → Gateway 실행. 기존 공개 체험의 고정 fixture와 분리된 운영 경로입니다.</p>
    {operator && <form className="ops-inline-form" onSubmit={prepare}><label>준비할 원본<select name="sourceId" required disabled={busy}><option value="">npm / tarball 원본 선택</option>{releases.filter(canPrepare).map(release => <option key={release.releaseId} value={release.releaseId}>{release.legacyReleaseId || release.toolId} · {short(release.releaseId)}</option>)}</select></label>
      <label>준비 전용 정책<select name="policyHash" required disabled={busy}><option value="">정책 선택</option>{policies.filter(isPreparationPolicy).map(policy => <option key={policy.policyHash} value={policy.policyHash}>{policy.alias} · {policy.version}</option>)}</select></label><button disabled={busy || !releases.some(canPrepare) || !policies.some(isPreparationPolicy)}>이미지 준비 요청</button></form>}
    <p className="ops-data-note">서버의 준비 worker·고정 builder·AI/critic 설정이 필요합니다. 미설정·판단 불가는 성공으로 대체하지 않습니다. URL·이미지 태그·호스트 경로·비밀값을 이 요청에서 지정할 수 없습니다.</p>
    {message && <p className="ops-message" role="status">{message}</p>}{error && <p className="ops-message error" role="alert">{error} · 상세의 이전 증거 표시는 숨겼습니다.</p>}
    <PreparationRecords jobs={jobs} releases={releases} operator={operator} busy={busy} onOpen={job => void perform(async () => { const next = await controlApi<{ preparation: Preparation }>(`preparations/${encodeURIComponent(job.preparationId)}`); setDetail(next.preparation); })} onRetry={job => void perform(async () => { await controlApi(`preparations/${encodeURIComponent(job.preparationId)}/retry`, {}); await onRefresh(); setDetail(null); setMessage("실패 작업을 다시 대기열에 넣었습니다. 실행 설정은 서버에 고정된 값을 유지합니다."); })} />
    {detail && <PreparationDetail job={detail} operator={operator} summary={summary} onSelect={onSelect} onEvidence={() => void perform(async () => { const [current, evidence] = await Promise.all([controlApi<{ preparation: Preparation }>(`preparations/${encodeURIComponent(detail.preparationId)}`), controlApi<ReceiptEvidenceSummary>(`preparations/${encodeURIComponent(detail.preparationId)}/evidence`)]); setDetail(current.preparation); setSummary(evidence); })} />}
    {operator && <p className="ops-data-note">응답이 불확실하면 같은 원본·정책으로 재시도하세요. 현재 화면은 요청 식별키를 유지합니다. 페이지를 다시 열기 전 목록에서 기존 작업을 확인하세요.</p>}
  </section>;
}
