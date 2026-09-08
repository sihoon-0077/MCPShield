import React, { useEffect, useState, type FormEvent } from "react";
import { controlApi } from "../lib/control-client";

export type SemanticEvidenceScope = { semanticEvidenceMode?: string; providerQuality?: string };
export type Release = SemanticEvidenceScope & { releaseId: string; legacyReleaseId: string; toolId: string; version: string; status: string; artifactDigest: string; toolSurfaceHash: string; policyHash: string | null; reportRoot: string | null; validUntil: string | null; sourceType?: string; runtimeProfile?: string; sourceReleaseId?: string; chainUnavailable?: boolean; chain: null | { chainId: number; registryContract: string; observedBlock: number; blockHash: string; txHash: string | null } };
export type Scan = { scanId: string; releaseId: string; policyHash: string; status: string; stage: string; attempts: number; maxAttempts: number; traceId: string; createdAt: string; updatedAt: string; nextAttemptAt: string; lastError?: unknown; result?: SemanticEvidenceScope & { state?: string; verdict?: string; validUntil?: string; reportRoot?: string; scanResult?: { scanStatus?: string } } };
export type ChainAction = { actionId: string; releaseId: string | null; kind: string; status: string; txHash: string | null; errorCode: string | null; chainId: number; registryAddress: string; createdAt: string; updatedAt: string };
export type Admission = { decision: string; status: string; reasonCode: string; releaseId: string; policyHash: string; source: string; checkedAt: string; traceId: string; signature?: string; snapshot?: { expiresAt: string; observedBlock: number; blockHash: string; chainId: number; registryContract: string; operationClass: string } };
const date = (value?: string | null) => value ? new Date(value).toLocaleString("ko-KR") : "기록 없음";
const short = (value?: string | null) => value ? `${value.slice(0, 12)}…${value.slice(-8)}` : "없음";
const actionName: Record<string, string> = { REGISTER_RELEASE: "릴리스 등록", PUBLISH_POLICY: "정책 공개", DEPRECATE_POLICY: "정책 폐기", ATTEST: "검증자 서명 제출", QUARANTINE: "긴급 격리", SYNC_EXPIRY: "만료 반영" };
const actionStatus: Record<string, string> = { NEW: "전송 대기", PREPARED: "서명 준비 · 전송 미확인", SUBMITTED: "전송됨 · 영수증 대기", COMPLETED: "처리됨 · 최종성은 별도 확인", FAILED: "실패" };
export const policyMatchesRelease = (release: Pick<Release, "runtimeProfile"> | undefined, policy: { document?: unknown }) => Boolean(release) && (policy.document as { profile?: string } | undefined)?.profile === release?.runtimeProfile;

export function SemanticEvidenceNotice({ evidence, oci = false }: { evidence?: SemanticEvidenceScope; oci?: boolean }) {
  if (!oci && !evidence?.semanticEvidenceMode && !evidence?.providerQuality) return null;
  return <p className="ops-data-note"><b>AI 증거의 범위 · API 제공 메타데이터</b><br />
    분석 출처: <code>{evidence?.semanticEvidenceMode ?? "미제공"}</code><br />모델 품질: <code>{evidence?.providerQuality ?? "미제공"}</code><br />
    {evidence?.semanticEvidenceMode === "LOCAL_CONTRACT_TEST" ? "로컬 합성 응답으로 분석 연동을 검사한 범위입니다. 상용 AI 모델의 탐지 품질을 측정하거나 승인한 결과가 아닙니다." : "분석 출처가 확인된 로컬 합성 모드인지 알 수 없습니다. 미제공·알 수 없는 출처를 임의로 추정하지 않습니다."}
    {evidence?.providerQuality === "PROVIDER_QUALITY_NOT_MEASURED" ? " 모델 품질은 미측정입니다." : " 모델 품질 수준은 이 화면에서 검증하지 않습니다."}
    {" "}네이티브 Docker 검사·검증자 서명·현재 실행 허가는 별도로 확인합니다.</p>;
}

export function ChainActionsView({ actions }: { actions: ChainAction[] }) {
  return <div className="ops-table-wrap"><table><thead><tr><th>작업 / 범위</th><th>전송 상태</th><th>트랜잭션</th><th>최근 변경</th></tr></thead><tbody>{actions.map((item) => <tr key={item.actionId}><td>{actionName[item.kind] ?? item.kind}<small>{item.releaseId ? "현재 릴리스" : "조직 정책 작업 · 적용 정책 확인 필요"}</small><small title={item.actionId}>{short(item.actionId)}</small></td><td><b>{item.status}</b><small>{actionStatus[item.status] ?? "알 수 없는 상태"}</small>{item.errorCode && <small className="ops-flow-error">{item.errorCode}</small>}</td><td><code title={item.txHash ?? ""}>{short(item.txHash)}</code><small>chain {item.chainId} · {short(item.registryAddress)}</small></td><td>{date(item.updatedAt)}</td></tr>)}</tbody></table>{!actions.length && <p className="ops-empty">불러온 내역에 체인 작업이 없습니다. 전송 또는 검증 완료로 간주하지 않습니다.</p>}</div>;
}

export function AdmissionView({ admission, now }: { admission: Admission | null; now: number }) {
  if (!admission) return <p className="ops-empty">아직 조회하지 않았습니다. 실행 판정은 아래 버튼으로 현재 API에 직접 확인하세요.</p>;
  const snapshot = admission.snapshot;
  const fresh = snapshot && Number.isFinite(Date.parse(snapshot.expiresAt)) && Date.parse(snapshot.expiresAt) > now;
  return <div className="ops-admission" aria-live="polite"><div><b>API 조회 결과: {admission.decision}</b><span className="ops-badge">{admission.source === "EVM" ? `EVM · chain ${snapshot?.chainId ?? "미제공"}` : `${admission.source} · 온체인 증명 아님`}</span></div>
    <p>{admission.reasonCode} · 상태 {admission.status}<br />조회 {date(admission.checkedAt)} · trace {short(admission.traceId)}</p>
    {snapshot && admission.signature ? <p>서명된 스냅샷 포함 · {admission.source === "EVM" && admission.decision === "ALLOW" ? "확정 허용 기준 블록 (API 제공)" : "판정 관측 블록"} {snapshot.observedBlock}<br />{fresh ? `유효기한 ${date(snapshot.expiresAt)}` : "스냅샷 만료 · 다시 조회해야 합니다."}</p> : <p>서명된 스냅샷이 없습니다. Gateway의 서명 기반 실행 허가 증빙으로 사용할 수 없습니다.</p>}
    <p>이 화면은 API 조회 시점의 결과입니다. 서명 검증·도구 실행은 하지 않으며, 실제 Gateway가 실행 직전에 다시 확인합니다.</p></div>;
}

export function ReleaseWorkflow({ release, scans, policies, actions, manage, onRefresh }: {
  release: Release; scans: Scan[]; policies: { policyHash: string; alias: string; deprecatedAt: string | null; document?: unknown }[]; actions: ChainAction[]; manage: boolean; onRefresh: () => Promise<void>;
}) {
  policies = policies.filter(policy => policyMatchesRelease(release, policy));
  const releaseScans = scans.filter((scan) => scan.releaseId === release.releaseId).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const [scanId, setScanId] = useState(releaseScans[0]?.scanId ?? "");
  const scan = releaseScans.find((item) => item.scanId === scanId) ?? releaseScans[0];
  const [fallbackPolicy, setFallbackPolicy] = useState(policies.find((item) => !item.deprecatedAt)?.policyHash ?? "");
  const policyHash = scan?.policyHash ?? fallbackPolicy;
  const policy = policies.find((item) => item.policyHash === policyHash);
  const [operationClass, setOperationClass] = useState("READ_PRIVATE");
  const [admission, setAdmission] = useState<Admission | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [now, setNow] = useState(Date.now());
  useEffect(() => { setAdmission(null); }, [policyHash, operationClass, release.status, release.chainUnavailable, release.chain?.blockHash]);
  useEffect(() => { if (!admission?.snapshot) return; const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, [admission]);
  const releaseActions = actions.filter((item) => item.releaseId === release.releaseId);
  const attestationActions = releaseActions.filter((item) => item.kind === "ATTEST");
  const visibleActions = actions.filter((item) => item.releaseId === release.releaseId || (item.releaseId === null && ["PUBLISH_POLICY", "DEPRECATE_POLICY"].includes(item.kind)));
  const ready = scan?.status === "COMPLETED" && scan.result?.state === "READY_FOR_VALIDATORS";
  async function perform(work: () => Promise<void>) {
    setBusy(true); setError(""); setMessage("");
    try { await work(); } catch (error) { setError(error instanceof Error ? error.message : "조회 실패"); }
    finally { setBusy(false); }
  }
  function enqueue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget; const target = new FormData(form).get("chainOperation");
    void perform(async () => {
      const path = target === "policy" ? `policies/${encodeURIComponent(policyHash)}/publish` : `releases/${encodeURIComponent(release.releaseId)}/register`;
      const { action } = await controlApi<{ action: ChainAction }>(path, {});
      form.reset(); setMessage(`${actionName[action.kind] ?? action.kind} 요청 접수 · ${action.status}. 접수만으로 블록체인 확정이나 실행 허용을 뜻하지 않습니다.`);
      await onRefresh();
    });
  }
  return <section className="ops-workflow" aria-label="V2 검증에서 실행 판정까지">
    <div className="ops-section-heading"><h3>검사 → 검증자 → 체인 → 실행 판정</h3><span className="ops-badge">V2 운영 API · REPLAY 아님</span></div>
    <p>연결된 API의 실제 기록입니다. 로컬 체인도 chain ID로 구분하며, 전송 접수와 실행 허용을 혼동하지 않습니다.</p>
    <SemanticEvidenceNotice evidence={scan?.result ?? release} oci={release.runtimeProfile === "restricted-oci-offline-v1"} />
    <div className="ops-flow-select"><label>확인할 검사<select value={scan?.scanId ?? ""} onChange={(event) => setScanId(event.target.value)} disabled={busy || !releaseScans.length}><option value="">검사 내역 없음</option>{releaseScans.map((item) => <option key={item.scanId} value={item.scanId}>{date(item.createdAt)} · {item.status} · {short(item.scanId)}</option>)}</select></label>{!scan && <label>실행 판정 정책<select value={fallbackPolicy} onChange={(event) => setFallbackPolicy(event.target.value)} disabled={busy}><option value="">정책 선택</option>{policies.map((item) => <option key={item.policyHash} value={item.policyHash}>{item.alias}{item.deprecatedAt ? " (폐기됨)" : ""}</option>)}</select></label>}</div>
    <p className="ops-data-note">현재 정책: {policy?.alias ?? "목록에서 확인 불가"} · <code>{policyHash || "선택 없음"}</code>{policy?.deprecatedAt ? " · DEPRECATED" : ""}</p>
    <ol className="ops-flow" aria-label="현재 증빙 단계">
      <li><span>01 · 검사</span><b>{scan?.status ?? "검사 전"}</b><small>분석 {scan?.result?.scanResult?.scanStatus ?? "미완료"}<br />검사 완료 ≠ 보안 통과</small></li>
      <li><span>02 · 증거 준비</span><b>{ready ? "READY" : "준비 미확인"}</b><small>{ready ? `권고 판정 ${scan.result?.verdict ?? "미제공"}` : "완료된 증거가 필요합니다."}<br />READY ≠ PASS</small></li>
      <li><span>03 · 검증자 제출</span><b>{attestationActions.length}건의 작업</b><small>불러온 릴리스 전체 이력<br />독립 검증자 수·quorum 아님</small></li>
      <li><span>04 · Registry 관측</span><b>{release.chainUnavailable ? "현재 조회 불가" : release.chain ? release.status : "체인 증빙 없음"}</b><small>{release.chain ? `chain ${release.chain.chainId} · block ${release.chain.observedBlock}${release.chainUnavailable ? " (이전 기록)" : ""}` : "인덱서 관측 기록이 필요합니다."}<br />{release.policyHash === policyHash ? "선택 정책의 관측 기록" : "선택 정책과 관측 정책을 비교하세요."}</small></li>
      <li><span>05 · Gateway 판정</span><b>{admission ? `API: ${admission.decision}` : "직접 조회 필요"}</b><small>도구 실행 여부는 확인하지 않음<br />아래에서 최신 판정 조회</small></li>
    </ol>
    <p className="ops-data-note">검증자는 외부 실행기에서 증거와 EIP-712 서명 대상을 검증한 뒤 제출합니다. 이 화면에서 개인키를 입력하거나 서명을 생성하지 않습니다.</p>
    <h3>전송 작업 기록</h3><p>NEW → PREPARED → SUBMITTED → COMPLETED. COMPLETED는 영수증 수신 또는 이미 반영된 작업이며, 최종 확인 수와 현재 실행 허가는 별도입니다. 정책 작업은 조직 전체 내역입니다.</p>
    <ChainActionsView actions={visibleActions} />
    {manage && <details className="ops-chain-admin"><summary>관리자 · 온체인 등록 요청</summary><p>설정된 서버 relayer가 트랜잭션을 전송합니다. 네트워크 가스 비용이 발생할 수 있습니다. 검증자 투표를 대신하지 않습니다.</p><form method="post" onSubmit={enqueue}><label>등록할 대상<select name="chainOperation" disabled={busy}><option value="release">현재 릴리스 등록</option>{policy && !policy.deprecatedAt && <option value="policy">선택 정책 공개 · {policy.alias}</option>}</select></label><label className="ops-check"><input type="checkbox" required disabled={busy} />위 릴리스/정책과 서버에 설정된 체인으로 전송을 요청합니다.</label><button disabled={busy}>온체인 등록 요청</button></form></details>}
    <h3>실행 직전 판정 확인</h3><p>strict 모드로 조회합니다. API가 연결되었다는 이유만으로 ALLOW를 만들지 않습니다.</p><div className="ops-flow-select"><label>도구가 하려는 작업<select value={operationClass} disabled={busy} onChange={(event) => setOperationClass(event.target.value)}><option value="READ_PRIVATE">조직 데이터 읽기</option><option value="READ_PUBLIC">공개 데이터 읽기</option><option value="WRITE_EXTERNAL">외부 시스템 쓰기</option><option value="DESTRUCTIVE">삭제·파괴적 작업</option><option value="FINANCIAL">금융 작업</option></select></label><button disabled={busy || !policyHash} onClick={() => void perform(async () => { setAdmission(null); const result = await controlApi<Admission>("admission/check", { releaseId: release.releaseId, artifactDigest: release.artifactDigest, toolSurfaceHash: release.toolSurfaceHash, policyHash, mode: "strict", operationClass }); setNow(Date.now()); setAdmission(result); })}>{busy ? "처리 중…" : "현재 실행 판정 조회"}</button></div>
    {error && <p className="ops-message error" role="alert">{error} · 설정되지 않은 기능은 완료로 표시하지 않습니다.</p>}{message && <p className="ops-message" role="status">{message}</p>}
    <AdmissionView admission={admission} now={now} />
  </section>;
}
