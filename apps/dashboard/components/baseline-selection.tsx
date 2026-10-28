import React from "react";
import { isBaselinePolicy, scopedNodePolicyMode, type Release } from "./release-workflow";

const exactId = (value: unknown): value is string => typeof value === "string" && /^0x[a-f0-9]{64}$/.test(value);
export const baselineSelectionError = "이전 실행 릴리스 또는 ‘비교하지 않음’을 다시 선택하세요. 목록·정책이 바뀌면 이전 선택을 사용할 수 없습니다.";

// Public metadata only narrows choices; the API checks tenant ownership, original evidence and operator authority.
export function baselineCandidates(releases: Release[], target: Release | undefined, document: unknown) {
  const sourceId = target?.runtimeProfile ? target.sourceReleaseId : target?.releaseId;
  if (!target || !exactId(sourceId) || !isBaselinePolicy(document)) return [];
  const mode = scopedNodePolicyMode(document);
  if (target.runtimeProfile ? target.runtimeProfile !== "restricted-node-docker-v2" || target.sourceType !== "prepared-npm" || target.semanticEvidenceMode !== mode : !["npm", "tarball"].includes(target.sourceType ?? "")) return [];
  return releases.filter(candidate => exactId(candidate.releaseId) && candidate.releaseId !== target.releaseId
    && candidate.toolId === target.toolId && candidate.runtimeProfile === "restricted-node-docker-v2"
    && candidate.sourceType === "prepared-npm" && exactId(candidate.sourceReleaseId) && candidate.sourceReleaseId !== sourceId
    && candidate.semanticEvidenceMode === mode);
}

export function baselineRequestFields(releases: Release[], target: Release | undefined, document: unknown, selection: string): { baselineReleaseId?: string | null } {
  if (!isBaselinePolicy(document)) return {};
  if (selection === "none") return { baselineReleaseId: null };
  if (baselineCandidates(releases, target, document).some(candidate => candidate.releaseId === selection)) return { baselineReleaseId: selection };
  throw new Error(baselineSelectionError);
}

export function BaselineSelect({ candidates, value, disabled, onChange }: { candidates: Release[]; value: string; disabled: boolean; onChange: (value: string) => void }) {
  return <><label>이번 검사의 비교 대상<select name="baselineReleaseId" required value={value} disabled={disabled} onChange={event => onChange(event.target.value)}>
    <option value="">비교 방법을 직접 선택하세요</option><option value="none">비교하지 않음</option>
    {candidates.map(candidate => <option key={candidate.releaseId} value={candidate.releaseId}>{candidate.legacyReleaseId || `${candidate.toolId}@${candidate.version}`} · {candidate.releaseId}</option>)}
  </select></label><p className="ops-data-note">현재 조직 목록에서 같은 도구·Node 실행 환경·분석 모드이고 원본이 다른 이전 실행 릴리스만 표시합니다. 후보 표시는 원본 증거·검사 권한의 검증이나 새 승인이 아닙니다. API가 최종 확인합니다. 비교하지 않음을 선택해도 현재 코드의 위험 검사는 진행합니다. 원본·릴리스·정책을 바꾸면 다시 선택하세요.</p></>;
}
