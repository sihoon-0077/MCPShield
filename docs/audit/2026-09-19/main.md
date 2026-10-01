# Main 감사 근거 — 비기능·지원 범위·문서 전체 경계

기준 코드: `7bac78a689b478e2aa6f4e2714a425d5c17a263b`, `master/main`.
이 파일은 종합 보고서의 입력이다. 여기의 행 수를 다른 파트의 행 수에 그대로 더하지 않는다.
동일 기능의 FR·상세 설계·테스트·발표 반복을 종합 보고서에서 한 요구사항으로 연결한다.

## 읽은 원문

원문 `MCPShield_전체_시스템디자인_해커톤_마스터문서.md`의 1–964,
3638–3775, 5556–5689, 5878–5997행을 검토했다. 마지막 5997행은 끝 빈 줄이다.
SHA-256: `702268984174af450276b5292a4afccd6a4d5dce79738fe3abde41c4d30d4ea2`.

- 1–430: 문제·제안서 원고·요약 요구. FR 및 제출 산출물과 매핑한다.
- 431–576: 50개 FR의 기준 문구. 각 FR은 종합표에서 한 번씩 집계한다.
- 577–649: 성능·보안·일관성·호환성. 구현 기능과 수치 달성을 분리한다.
- 650–779: 위협 모델·불변식은 연결된 방어 기능의 수용 조건이다. 공격자 한 명마다 새 기능을 세지 않는다.
- 780–807: MVP뿐 아니라 Pilot/Production 확장도 사용자 요청의 전체 범위에 포함한다.
- 810–964: QPS·사용자·비용 숫자는 문서가 명시한 설계 가정이다. 실제 매출·고객·5천만 호출 달성 요구로 변환하지 않는다. tiering·보존·egress 제한 등 구체적 메커니즘은 평가한다.
- 3638–3775: 기존 FR의 선택 이유가 대부분이다. OPA bundle 및 강한 격리의 후속 범위는 별도 평가한다.
- 5556–5689: 레퍼런스 목록 자체를 구현 기능 27개로 세지 않는다. 제출 직전 출처 재검증은 제출 검수 조건이다. 논문의 탐지율을 제품 성능으로 옮기지 않는다.
- 5878–5921: ADR-001–007은 기존 식별·AI·격리·Gateway 요구의 반복이다.
- 5923–5970: 용어집은 기능이 아니다.
- 5972–5997: 5개 MVP 성공 조건은 기존 FR 및 성능 실험의 재요약이다.

## 독립 추가 요구 후보

`부분`은 관련 구현 또는 측정은 있으나 전체 수용 조건 미충족, `미완료`는 해당 결과/기능의 증거를 찾지 못함이다.
일반적인 테스트 통과를 실제 운영 SLO 달성으로 바꾸지 않는다.

| ID | 원문 행 | 요구사항 | 상태 | 확인 근거와 남은 조건 |
|---|---|---|---|---|
| MA-01 | 583 | cache admission p95 MVP 30ms / Pilot 20ms | 부분 | `scripts/ops/evaluate-admission.ts`, `tests/integration/admission-measure.test.ts`. 실제 서명 캐시 경로 측정기는 있으나 완료된 대표 부하 결과 없음. 1만 identity 실험은 PARTIAL_FAILED. |
| MA-02 | 584 | indexer admission p95 MVP 250ms / Pilot 150ms | 부분 | 같은 실제 EVM/HTTP 측정기와 CI smoke. 운영 indexer 및 대표 부하 p95 미검증. |
| MA-03 | 585 | RPC fallback p95 MVP 1.5초 / Pilot 800ms | 부분 | `apps/gateway/src/admission-fallback.mjs`, `packages/contracts-sdk/src/transport.mjs`의 총 시간 예산은 구현. 타임아웃 설정은 지연 SLO 달성 증거가 아님. |
| MA-04 | 586 | 100MB 이하 패키지 정적 분석 시간 목표 | 부분 | 정적 scanner·실측 fixture 결과 있음. 다양한 크기/언어/의존성 표본의 60초 및 p95 90초 수용 결과 없음. |
| MA-05 | 587 | 실제 AI 의미 분석 p95 45초 / 20초 | 부분 | `ai-transport.mjs` deadline·usage 기록/계약 HTTP 검증. 실제 외부 모델의 대표 표본 latency 미측정. |
| MA-06 | 588 | 샌드박스 검사 3–10분 / p95 10분 | 부분 | native Linux 검사 성공 이력과 timeout 있음. 대표 패키지군의 반복 분포/처리량 검증 없음. |
| MA-07 | 589 | 격리 event→Gateway 차단 p95 30초 / 15초 | 부분 | 두 Gateway 차단·호출 직전 상태 재검사 검증. 다음 호출 없는 지속 세션의 즉시 중단 및 반복 전파 분포 미측정. |
| MA-08 | 595 | Pilot API 99.5% / Production 99.9% 가용성 | 미완료 | readiness·metrics 코드는 존재하지만 운영 기간/오류 예산/가용성 달성 증거 없음. |
| MA-09 | 598 | 최소 두 독립 RPC에서 폐기 기록 재구성 | 부분 | 복수 RPC failover와 reorg/reconcile 테스트 있음. 두 독립 외부 제공자에서 재구성한 운영 증거 없음. |
| MA-10 | 617, 871–876 | 외부 LLM에 전체 소스·환경·고객 데이터 비전송 | 부분 | scoped Node v2는 provenance·합집합 disclosure budget·고정 DTO와 zero-call 거부 회귀를 구현. 전체 호출 경로가 v2로 바뀐 것은 아니며 OCI v2는 별도 브랜치. 알려지지 않은 민감 데이터의 완전한 판별도 아님. |
| MA-11 | 793 | PyPI wheel/sdist 입력 지원 | 미완료 | 현재 resolver는 npm/tarball/OCI. OCI 안의 Python 텍스트 지원은 PyPI 수집·설치 adapter가 아님. |
| MA-12 | 794 | macOS·Windows Gateway adapter | 부분 | Node 기반 stdio/HTTP demo는 Windows 회귀가 있으나 attested runtime의 지원 실행 환경은 Linux Docker. macOS·Windows native 정책 adapter/검증 matrix 미완성. |
| MA-13 | 795 | private package registry OIDC | 미완료 | `registry-broker.mjs`는 고정 공개 registry metadata broker. GitHub CI의 OIDC 서명은 후보 private registry OIDC 입력이 아님. |
| MA-14 | 796 | remote Streamable HTTP metadata pinning | 미완료 | 공개 `/mcp` 서버는 제공자 역할. 임의 원격 MCP를 pinning하는 upstream proxy·metadata-only assurance 기능과 다름. |
| MA-15 | 798 | 후보 artifact의 Sigstore provenance 입력 검증 | 미완료 | 자체 배포 이미지 attestation workflow와 후보 공급망 provenance 수집·검증은 별개다. |
| MA-16 | 802 | 재현 가능한 build 및 SLSA provenance | 부분 | 불변 입력·이미지 hash·GitHub provenance/SBOM 서명 workflow와 과거 성공 산출물 있음. 동일 입력의 bit-for-bit 재현 및 정식 수준 검증, 최신 전체 성공 미확인. |
| MA-17 | 803, 3716–3724 | Docker보다 강한 격리 tier (gVisor/microVM/WASI 등) | 미완료 | 현재 readonly/nonroot/cgroup/network 제한 Docker. 후보 대안 전부를 동시에 도입해야 한다는 뜻은 아니나 실제 stronger-isolation tier 없음. |
| MA-18 | 804 | TEE runtime attestation | 미완료 | 실제 TEE quote 검증/배포 증거 없음. Docker image digest는 TEE attestation이 아님. |
| MA-19 | 805, 3694 | 다기관 독립 validator 운영 | 미완료 | 별도 source·key·재검사 프로세스는 구현. 독립 기관 참여·키 관리·다양성/책임 운영 증거 없음. |
| MA-20 | 806 | multi-chain read 또는 canonical chain mirror | 미완료 | chain/contract domain 분리는 구현됐으나 체인 간 상태 동기화·mirror 소비 기능 없음. |
| MA-21 | 807 | registry/IDE vendor native integration | 미완료 | 사용자가 설정하는 MCP wrapper와 자체 HTTP endpoint는 있음. vendor 자체 제품에 들어간 integration은 없음. |
| MA-22 | 872–876 | 위험도별 Tier 0–3 분석 분기·추가 모델/probe | 부분 | static 무AI, scoped Node metadata/snippet·tier3 다중 실제 응답 model ID/더 많은 probe 계약 검사 구현. 전체 artifact/profile 자동 분기와 외부 모델 효율·품질 실험은 미완료. |
| MA-23 | 896–902 | artifact/trace/log hot·warm 보존 및 appeal hold | 부분 | 암호화 content-addressed evidence·이의제기 이력 보존 있음. 7/90일 artifact, 30/180일 trace, 30일 admission log 정책의 실제 lifecycle/hold 집행 없음. 숫자는 원문 권장값이며 정책의 존재/검증을 평가. |
| MA-24 | 901, 618 | raw packet/body 기본 비수집 | 완료 | `services/exfil-sink/server.mjs`: canary를 메모리에서 관찰하고 body를 전달/저장하지 않음. `tests/security/egress-proxy.test.mjs`가 raw/binary/invalid JSON canary·비노출 확인. 공개 chain은 digest만. |
| MA-25 | 915 | per-scan byte/DNS/domain/connection egress quota | 부분 | synthetic allowlist≤32, body≤16KiB, event≤1024, timeout·외부 기본 차단 있음. 실제 외부 목적지용 누적 byte/DNS/연결 수 예산은 별도 구현 필요. |
| MA-26 | 928–935, 3744–3752 | PASS 릴리스 Merkle batch 및 inclusion 기반 admission | 미완료 | action receipt batch(FR-407)는 다른 기능. 정상 릴리스 PASS batch finalization·Gateway inclusion 승인 경로는 없음. MVP 제외였지만 전체 확장 범위에는 남김. |
| MA-27 | 3726–3732 | Pilot OPA bundle 정책 분리 | 미완료 | 현재 versioned TypeScript 정책은 MVP 선택을 충족. OPA bundle 배포·서명·검증 adapter는 없음. |

## FR/다른 파트와 중복되는 조건 (여기서는 별도 집계하지 않음)

| 원문 | 매핑 |
|---|---|
| 596, 610, 622, 647 | FR-305/306 signed cache·bounded staleness·strict fail-closed |
| 597 | 관측성/indexer lag 추가 요구 (Frontend/Backend 상세 감사에서 통합) |
| 599, 605 | FR-404/405 durable transaction/queue |
| 606, 645 | FR-202 및 Evidence Bundle 무결성 |
| 607, 642 | FR-205 unique validator |
| 608–609 | FR-210 + reorg/confirmation/indexer 상세 수용 조건 |
| 615, 648, 734 | FR-107–109/303 격리 |
| 616 | FR-110 canary만 주입 |
| 618 | FR-209 chain 원문/PII 금지 |
| 619 | tenant encryption 추가 조건은 Backend object storage 감사에서 통합 |
| 620 | Backend validator key custody 조건 |
| 621, 644 | FR-113 AI-only 영구 폐기 금지 |
| 623 | Backend 요청 경계/제한 + 각 scanner 입력 경계 |
| 624 | Frontend/운영 로그 비밀 비노출 |
| 628–634 | FR-006/304/309/310, pagination·annotations·bounded schema 수용 조건 |
| 640–649 | INV-01→FR-002/004, 02→208, 03→205, 04→305, 05→113, 06→202, 07→302, 08→306, 09→107/109/303, 10→201 |
| 797 | Backend tenant policy profile |
| 835, 950–959 | Backend/Frontend 확장 감사. Redis 등의 제품명 자체를 새 기능으로 세지 않고 hot-read cache·분산 제한·coalescing 기능을 평가 |
| 3684 | quick scan·trusted publisher priority·긴급 승인: 상세 파트의 queue 및 break-glass와 통합 |
| 3754–3762 | Security 정적 AST/dataflow 요구와 통합 |
| 3764–3772 | Frontend 고위험 action 사용자 확인 요구와 통합 |

## 실제 실행 증거 경계

- Main `e55c1ab`: 전체 `npm test` 종료 0 및 기본 Next Turbopack 포함 `npm run build` 성공.
- Main `1686547`: client/BFF/release-readiness 14 PASS, backend typecheck 성공.
- `benchmarks/results/admission-matrix-10000-2026-09-09.json`: 99,000 예정 중 79,000 요청 완료,
  15개 cell 검증, `PARTIAL_FAILED`. 완료된 전체 matrix 또는 운영 성능이라고 세지 않는다.
- `benchmarks/results/mcptox-static-2026-09-09.json`: 485 poisoned record 중 review signal 126,
  25.98%. static review 지표이며 FPR·실제 agent ASR·전체 보안 탐지율이 아니다.
- native Docker/외부 환경 증거는 종합 보고서의 CI 기준 시각과 SHA를 따른다.
- OCI 추가 scanner `8c13b9c`는 별도 worktree checkpoint. Security 132 PASS/20 native 또는 gated SKIP,
  backend typecheck 성공을 담당자가 보고했으나 Main 통합·native 새 gate 성공은 아니다.
