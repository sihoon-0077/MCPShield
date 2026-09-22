import React, { useRef, useState, type FormEvent } from "react";
import { controlApi } from "../lib/control-client";
import { policyMatchesRelease, type Release } from "./release-workflow";

export type ScanPolicy = { policyHash: string; alias: string; version?: string; deprecatedAt: string | null; document?: unknown };
export type AppealScanScope = { appealId: string; toolId: string; artifactDigest: string; policyHash: string | null };
export const scanPolicyAllowed = (release: Release | undefined, policy: ScanPolicy, appeal?: AppealScanScope) => Boolean(release)
  && !policy.deprecatedAt && policyMatchesRelease(release, policy)
  && (!appeal || release!.toolId === appeal.toolId && (release!.artifactDigest !== appeal.artifactDigest || Boolean(appeal.policyHash && policy.policyHash !== appeal.policyHash)));

// The normal scan and appeal rescan share profile checks, fields and logical-attempt keys.
export function ScanRequestForm({ releases, policies, appeal, disabled = false, onRefresh }: {
  releases: Release[]; policies: ScanPolicy[]; appeal?: AppealScanScope; disabled?: boolean; onRefresh: () => Promise<void>;
}) {
  const [releaseId, setReleaseId] = useState(""), [policyHash, setPolicyHash] = useState("");
  const [pending, setPending] = useState(false), [error, setError] = useState(""), [message, setMessage] = useState("");
  const attempt = useRef<{ signature: string; key: string } | null>(null), active = useRef(false);
  const candidates = releases.filter(release => policies.some(policy => scanPolicyAllowed(release, policy, appeal)));
  const target = candidates.find(release => release.releaseId === releaseId);
  const matching = policies.filter(policy => scanPolicyAllowed(target, policy, appeal)), busy = disabled || pending;
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (active.current || busy) return;
    if (!matching.some(policy => policy.policyHash === policyHash)) { setError("조건과 프로필에 맞는 릴리스·정책을 다시 선택하세요."); return; }
    const body = { releaseId, policyHash, ...(appeal ? { appealId: appeal.appealId } : {}) }, signature = JSON.stringify(body);
    if (attempt.current?.signature !== signature) attempt.current = { signature, key: crypto.randomUUID() };
    active.current = true; setPending(true); setError(""); setMessage("");
    try {
      await controlApi("scans", body, "POST", attempt.current.key); await onRefresh();
      attempt.current = null; setReleaseId(""); setPolicyHash(""); setMessage("검사 요청 기록을 다시 조회했습니다. 실행 승인은 별도입니다.");
    } catch (error) { setError(error instanceof Error ? error.message : "검사 요청 실패"); }
    finally { active.current = false; setPending(false); }
  }
  return <form method="post" className="ops-inline-form" aria-label={appeal ? `이의제기 ${appeal.appealId} 새 검사` : "새 검사 요청"} onSubmit={submit}>
    <p className="ops-data-note" id={appeal ? `rescan-help-${appeal.appealId}` : "scan-request-help"}>{appeal ? "OPEN 이의제기당 새 검사 1개만 연결합니다. 같은 도구의 artifact digest가 달라지거나 접수 당시와 다른 정책이어야 합니다. 릴리스 ID만 바꾸는 것은 충분하지 않습니다. 기존 결과 캐시를 재사용하지 않으며 원본 판정은 유지합니다. " : "릴리스 실행 프로필과 일치하는 활성 정책만 선택할 수 있습니다. "}응답이 불확실하면 먼저 새로고침하세요. 같은 선택으로 재요청하면 현재 화면의 재시도 식별키를 유지합니다.</p>
    <label>검사할 릴리스<select name="releaseId" required value={releaseId} disabled={busy} onChange={event => { setReleaseId(event.target.value); setPolicyHash(""); }}><option value="">릴리스 선택</option>{candidates.map(release => <option value={release.releaseId} key={release.releaseId}>{release.legacyReleaseId || `${release.toolId}@${release.version}`} · {release.runtimeProfile ? "실행 릴리스" : "원본"} · {release.releaseId}</option>)}</select></label>
    <label>프로필에 맞는 정책<select name="policyHash" required value={policyHash} disabled={busy || !target} onChange={event => setPolicyHash(event.target.value)}><option value="">정책 선택</option>{matching.map(policy => <option value={policy.policyHash} key={policy.policyHash}>{policy.alias} · {policy.version}</option>)}</select></label>
    {!candidates.length && <p className="ops-empty">조건에 맞는 릴리스·활성 정책이 없습니다. 같은 도구의 수정본을 등록하거나 관리자에게 정책 등록을 요청하세요.</p>}
    <button disabled={busy || !matching.some(policy => policy.policyHash === policyHash)} aria-describedby={appeal ? `rescan-help-${appeal.appealId}` : "scan-request-help"}>{appeal ? "새 검사 요청 · 이의제기에 연결" : "검사 요청"}</button>
    {error && <p className="ops-message error" role="alert">{error}</p>}{message && <p className="ops-message" role="status">{message}</p>}
  </form>;
}
