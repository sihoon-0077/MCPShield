# MCPShield 캡스톤 v2.0 — 1차 구현 결과

2026-09-22 KST. 통합 기능/검사 기준 `c3c46dc`, 브랜치 `master/main`.
**전체 v2.0 완료 보고가 아니다.** 기존 50% 사용량 중단 조건은 사용자 재개 요청으로 해제했다.
기준은 [최종 마스터 v2.0](MCPShield_캡스톤_최종_마스터문서_v2.0.md)의 P0 40개다.

## 이번에 실제 반영한 것

| 파트 | 반영 | 아직 구분해야 할 것 |
|---|---|---|
| Security | scoped 악성 fixture가 기존 sink JSON 계약을 사용하도록 수정; 실제 Ed25519 게시자 서명·고정 공개키·source bytes 검증 | 서명 유효성은 행동 안전성 아님. 게시자 설정의 API/UI·전체 pipeline 연결은 남음 |
| Backend | chain outbox 최대12회/5분, 1초→최대30초 backoff, DLQ·원인/시도 기록 | 불명확한 signed transaction은 삭제/재서명하지 않음. 해당 signer를 멈추고 운영자가 체인 사실을 확인 |
| Gateway | 기존 모델 결정 함수→MCP SDK→strict Gateway→실제 `list_messages` 호출 연결; 승인/후속 호출 identity 로그 | 로컬 가짜 모델 계약 검사와 실제 외부 모델 실증을 구분. 보호 ON 전용이며 OFF/ON ASR 아님 |
| 화면 | 체인 재시도 중단 한국어 안내·시도 횟수·다음 확인 시각 | 최신 공개 배포·실제 브라우저 전체 검수는 하지 않음 |
| Main/CI | 새3개 worktree, 교차 리뷰·통합; prepared Agent 및 PostgreSQL outbox native 테스트를 CI에 연결 | 새 통합 SHA의 Linux 전체 성공은 별도 확인 필요 |

ponytail 적용: 기존 resolver/hash·SQL outbox·Agent 판단 함수·MCP SDK를 재사용했다.
새 패키지·서비스·Redis/Kafka/RabbitMQ를 도입하지 않았다. 보안 guard·FAIL 기대값을 낮추지 않았다.
원본 `mcp/main`, 기존 worktree 및 공개 `/try`·`/mcp`를 보존했다.

## 로컬 검증

Windows / Node 24.13.0. `c3c46dc`에서 `npm test` exit 0.

| 검사 | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| Backend / 계약 / 통합 | 144 | 0 | 12 |
| Security | 133 | 0 | 19 |
| Gateway | 120 | 0 | 3 |
| Dashboard | 42 | 0 | 1 |
| 합계 | **439** | **0** | **35** |

- Replay smoke, MCP SDK E2E, LIVE synthetic smoke 모두 PASS.
- `npm run build`: backend 타입 검사 및 Next.js production build PASS (`c690226`; 이후 변경은 CI 계약 테스트뿐).
- 빌드된 화면의 `MCPSHIELD_FORM_HTTP_TESTS=1` 검사: 3 PASS / 0 SKIP.
- 35 SKIP은 PostgreSQL·Linux/Docker·일부 opt-in 검사다. 위의 별도 HTTP 실행을 전체 suite의 SKIP에서 빼서 집계를 바꾸지 않았다.
- 신규 40개 증거 지도: P0 ID 40개, 중복 없음, master 순서와 정확히 일치.
- 초기 통합 검사에서 CI 명령 문자열을 고정한 회귀 테스트 1개가 실패했다. 새 native 검사 목록을 포함하도록 기대 계약을 갱신하고, 기존 image-signing 성공 조건을 유지하는 검사를 보강한 뒤 전체를 다시 실행했다.

## Linux CI와 리뷰

- 수정 전 `9a251ae`의 [CI 35696784563](https://github.com/sihoon-0077/MCPShield/actions/runs/35696784563)는 scoped scanner/API 2 FAIL이었다.
- fixture 수정 `35019f6`의 [CI 35736644460](https://github.com/sihoon-0077/MCPShield/actions/runs/35736644460)에서 기존에 실패하던 **scoped Node scanner 및 scoped API→독립 validator→Gateway native 두 gate가 모두 PASS**했다. Linux sandbox 격리·Node24·PostgreSQL job도 PASS했다. 이 기록 시 Node22의 후속 Compose 등 전체 job은 아직 종료 전이다.
- 이 CI에는 이후 게시자/재시도/Agent 변경이 없다. 결과를 새 통합 SHA의 native 성공으로 전용하지 않는다.
- Main과 별도 Security reviewer가 queue head/nonce 보존·Agent 결과 판정·키 분리·모델 증거 표기를 검토했다. 발견한 legacy unsigned queue 정체, PostgreSQL migration 기대값, scoped mail 응답 호환, 다중 호출 완료 오판은 수정했다.
- 새 통합 `fab3ed1`의 [CI 35738979192](https://github.com/sihoon-0077/MCPShield/actions/runs/35738979192): PostgreSQL job PASS(신규 outbox claim/backoff/계정 lease/signed DLQ 검사 포함, 47 PASS / 0 FAIL / 1 SKIP), Node24 job PASS. PostgreSQL의 1 SKIP은 Docker health opt-in 검사이며 SQL retry 검사의 SKIP이 아니다.
- 같은 통합 CI의 Node22 prepared Gateway/Agent native 단계는 실패했다. Windows의 SKIP을 성공으로 취급하지 않았기에 발견한 실패이며, 상세 로그 확인과 수정 전까지 해당 기능의 native 완료로 세지 않는다. scoped Node scanner 등 후속 native 단계는 별도로 성공했다.
- 두 Gateway 테스트가 같은 Docker daemon의 전체 컨테이너 목록을 검사하면서 병렬 실행되는 충돌을 교차 리뷰에서 발견했다. 누수 검사를 유지하고 `--test-concurrency=1`을 고정했으며, CI 명령 계약 검사 9개가 PASS했다. 실제 실패 로그 및 후속 native 결과 확인 전에는 이것만으로 원인 해결을 확정하지 않는다.
- 같은 SHA의 PR run에서는 OCI worker/validator native 단계도 실패했으나 push run에서는 성공했다. 원인 미확정으로 별도 추적한다. P0 Node 경로 성공과 P1 OCI 경로 성공을 혼동하지 않는다.
- main 머지·Railway 재배포·테스트넷 거래·유료 모델 호출은 하지 않았다. 개발 PR은 검증 대기 상태로 유지한다.

## 로컬 성능 smoke (정식 평가와 구분)

깨끗한 `fab3ed1`에서 `node --import tsx scripts/ops/evaluate-admission.ts --requests 100 --concurrency 4 --identities 4` exit 0.
기존 측정기를 재사용했으며 8개 phase 각각 100회, 총 800회 집계다.

| 경로 | p50 | p95 | 결과 |
|---|---:|---:|---|
| strict HTTP + local EVM, 동일 identity | 63.238 ms | 82.821 ms | ALLOW 100/100 |
| strict HTTP + local EVM, 4 identities | 60.006 ms | 67.206 ms | ALLOW 100/100 |
| 폐기 후 admission | 48.572 ms | 54.201 ms | BLOCK 100/100, ALLOW 0 |

원본 집계는 로컬 `artifacts/capstone/admission-smoke-100-fab3ed1.json`에 있다(생성 artifact로 Git 제외).
실제 테스트넷·후보 hash/spawn 비용·개별 요청 지연 원자료를 포함하지 않아 CAP2-504 완료 증거가 아니다.
실행 중 Ganache의 Node24 µWS fallback 및 listener 경고가 있었다. 묵음 처리하거나 성능 실증의 환경 한계를 숨기지 않는다.

## 로그와 새 기능 확인 위치

- Dashboard `/console` → 릴리스 workflow의 **체인 작업**: 시도 횟수·다음 확인·자동 재시도 중단 안내.
- 인증된 `GET /v1/chain/actions/:actionId`: `attempts`, `retryStartedAt`, `nextAttemptAt`, `retryBudget`, `errorCode`.
- 인증된 `GET /v1/events`, 릴리스 history: `chain.action.retry_scheduled`, `chain.action.failed`, `chain.action.dead_letter`.
- Agent 실행: [Gateway README](../apps/gateway/README.md)의 환경/명령. `node benchmarks/gateway-agent.mjs`는 운영자 prepared identity·승인 설정·모델 opt-in 없이는 거부된다.
- 게시자 최소 검사: `node --import tsx --test tests/security/demo-publisher.test.mjs`.
- DB 변경/복구: [database README](../database/README.md). live DB에서 DLQ나 signed bytes를 지우고 재전송하면 안 된다.

## 다음 단계 / 완료로 세지 않은 것

1. 새 통합 SHA의 native PostgreSQL·prepared Agent·scoped source→validator→Gateway CI를 확인한다.
2. 게시자 검증을 운영자 source catalogue와 API/UI 증거 흐름에 연결한다.
3. 승인된 실제 모델로 Agent 정상 조회 및 scanner 의미 분석 증거를 확보한다. 모델/키·전송 범위·총 비용 상한이 필요하다.
4. Base Sepolia 실제 배포·승인/폐기 거래와 두 Gateway 반영을 검증한다. 테스트 전용 key/RPC/test ETH·거래 승인이 필요하다.
5. 독립 holdout 정상20/공격20·두 사람 label 검토·5개 비교군·실제 Agent OFF/ON·경로별100회 성능 측정을 수행한다.
6. 같은 RC의 clean E2E10회·브라우저 검수·PPTX/PDF·영상·최종 완료 ledger를 묶는다.

현재 CAP2 전체 완료율은 **아직 미산정**이다. [40개 증거 지도](capstone-evidence-map.md)는 검수 계획이지 완료 선언이 아니다.
실제 모델/체인/평가 증거가 없는 상태를 테스트 fixture 성공만으로 채우지 않는다.
