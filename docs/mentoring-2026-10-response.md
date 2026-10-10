# 1차 멘토링(2026-10) 반영 결과

| 항목 | 내용 |
|---|---|
| 작성일 | 2026-10-11 |
| 작업 브랜치 | `capstone/mentoring-v2.1` |
| 기준 문서 | [캡스톤 최종 마스터 문서 v2.1](MCPShield_캡스톤_최종_마스터문서_v2.1.md) (v2.0은 [그대로 보존](MCPShield_캡스톤_최종_마스터문서_v2.0.md)) |
| 이 문서의 역할 | 받은 의견(M1~M19)별로 우리 판단, 한 일, 근거 위치, 남은 일을 한 곳에 정리 |

**요약.** Control·Trust·Gateway의 세 영역 구조는 그대로 두고, 그림을 "릴리스마다 한 번 도는 검증 흐름"과 "도구 호출마다 도는 실행 통제 흐름"으로 나눠 다시 그렸습니다. 비어 있던 "검증자가 참여할 이유"는 **MCP를 실제로 쓰는 회사들이 검증자를 맡는 컨소시엄**으로 정했습니다(ADR-003). "블록체인이 없으면 무엇이 깨지는가"는 **운영사 서명 권한이 장악되거나 운영사가 멈춘 장면**으로 정했고, 이 장면을 로컬 EVM(Ganache) 자동 통합 테스트로 구현했습니다. 최종 시연 경로는 ReleaseRegistryV2와 서명 admission 하나로 고정했습니다. 요청하신 실행 비용 측정 3종(호출 지연, 격리 후 차단까지 걸린 시간, 장애 시 읽기·쓰기 처리)도 추가했습니다. 다만 **Base Sepolia 실측, 실제 AI 모델 연결, docker compose·대시보드의 두 회사 구성 이전은 아직 하지 않았습니다.** 측정 수치는 깨끗한 작업 트리의 공식 측정(커밋 `f85f8e8`, Windows 개발 PC·Node v24.13.0, 표본 50) 값입니다([결과 JSON](../benchmarks/results/consortium-scene-f85f8e8-2026-10-10T18-00-42-747Z.json)).

---

## 바로 결론

- **구조 유지.** 세 영역은 그대로 둡니다. 다만 검증 흐름(릴리스마다 한 번, 실행 경로 밖)과 실행 통제 흐름(도구 호출마다, 사용자가 기다리는 경로)을 나눠 그렸고, Gateway A·B가 판정을 **어디서 조회하는지** 그림에 표시했습니다([v2.1 §4.1](MCPShield_캡스톤_최종_마스터문서_v2.1.md)).
- **검증자 = 쓰는 회사 컨소시엄.** MCP 도구를 업무에 쓰는 회사 보안팀들이 검사 비용을 나눠 지고, 참여사만 조기 경보와 판정 근거 원문(보고서·증거)을 받습니다. 데모의 검증자 키 3개는 **팀이 직접 운영**하며, 이 사실을 발표와 화면에 밝힙니다([ADR-003](adr-003-validator-consortium.md)).
- **블록체인이 필요한 장면 구현(로컬 EVM).** 운영사의 admission 서명 키가 장악되면, 운영사만 믿는 Gateway A는 자기가 직접 보지 못한 폐기에 대해 위조된 ALLOW 판정을 그대로 받아들이지만(앞 장면에서 폐기를 보고 기록해 둔 A는 그 기록으로 거부), 자체 Control API로 체인을 읽는 회사 B의 Gateway B는 폐기된 버전을 막습니다. 운영사가 멈추면 A는 안전하게 멈추고(fail-closed, 실행 중 세션의 다음 호출을 거부하고 세션 종료) B는 계속 일합니다. 처음 구상한 "운영사 DB 조작" 장면은 코드상 성립하지 않아 바꿨습니다. 운영사 API가 요청마다 체인을 다시 읽기 때문인데, 이는 그 자체로 장점입니다([ADR-004](adr-004-blockchain-necessity-scene.md)).
- **V2 단일 본선 경로.** `master/main` + ReleaseRegistryV2 + 서명 `/v1` admission, Gateway A → 운영사 API, Gateway B → 회사 B 자체 API로 고정했습니다. V1·무서명 `/api` 등은 지우지 않고 "확장"으로 표시합니다. **기본 docker compose는 아직 V1이라 이전은 다음 단계입니다**([ADR-005](adr-005-capstone-demo-path.md)).
- **측정 3종 추가.** (a) 같은 도구 호출의 지연을 직접 연결, Gateway A 경유, Gateway B 경유로 나눠 p50/p95 직접 0.24/0.45 ms, A 62.87/80.56 ms, B 61.69/79.76 ms(stdio Gateway 기준, HTTP serve 모드는 미측정), (b) 검증자가 체인에 직접 보낸 긴급 격리의 영수증을 확인한 뒤 이미 열린 세션에서 각 Gateway가 다음 호출을 거부하기까지 A 126 ms, B 126 ms(로컬 즉시 채굴 기준의 하한값, 2-of-3 FAIL 폐기의 세션 전파는 아직 미측정), (c) 운영사 장애 시 strict·balanced 모드별 읽기·쓰기 처리표(5개 경우 모두 테스트가 단언, 만료 캐시 포함). 문서에 있던 "93ms"는 스캐너 실행 시간이라 이 지표들과 관계없습니다.

아직 안 된 것: Base Sepolia 배포·실측, 실제 외부 AI 모델 연결, compose·대시보드의 V2 두 회사 스택 이전, 멀티시그·타임락 구현.

---

## 항목별 반영표

- 상태 표기: **반영 완료**(문서·결정·설정 완료), **로컬 구현·검증**(로컬 EVM 자동 테스트로 구현·확인, 테스트넷과 화면은 아님), **다음 단계**(결정은 했지만 구현 전).
- 장면 하네스와 테스트는 [`tests/integration/consortium-scene.ts`](../tests/integration/consortium-scene.ts), [`tests/integration/consortium-scene.test.ts`](../tests/integration/consortium-scene.test.ts)입니다(커밋 `9c7bc9d`). 장면이 지켜야 할 조건은 하네스의 `assertConsortiumReport` 한 곳에 있고, 테스트는 이를 표본 5로 확인합니다. 테스트는 `npm run test:backend`(CI의 `npm test`)에 포함됩니다. 아직 CI 실행 결과는 없으며 PR 후 확인합니다. 측정은 [`scripts/ops/evaluate-consortium-scene.ts`](../scripts/ops/evaluate-consortium-scene.ts)(`npm run evaluate:consortium-scene`, 기본 표본 50)로 실행하고, 결과는 `benchmarks/results/consortium-scene-<커밋 7자리>-<측정 시각>.json`에 저장됩니다(`--allow-dirty`로 실행하면 이름에 `-dirty-<소스 해시 8자리>`가 붙습니다). 이 스크립트는 같은 조건 함수를 통과하지 못하면 결과를 쓰지 않고, 작업 트리가 깨끗하지 않으면 거부하며(`--allow-dirty`는 결과에 기록), 기존 파일을 덮어쓰지 않습니다.
- 장면 하네스의 공통 한계: 로컬 Ganache 체인(Base Sepolia 아님), 스캐너는 고정 보고서를 돌려주는 **REPORT FIXTURE 테스트 대역**(실제 Docker 검사 없음), 두 회사가 같은 로컬 RPC 사용, 검증자 서명은 팀이 운영하는 테스트 키입니다. 또 장면 하네스의 검증자는 운영사 API가 준 서명 템플릿에 그대로 서명하며 독립 재검사(`prepared-verification`)를 거치지 않습니다. 따라서 CAP2-202(독립 검증)의 증거가 아닙니다. 컨소시엄 운영에서는 검증자가 운영사 템플릿이 아니라 자체 재검사 결과에 서명해야 합니다. 결과 JSON도 이 한계를 `environment`(`LOCAL_EVM_GANACHE`, `REPORT_FIXTURE_TEST_DOUBLE`, `SINGLE_INSTITUTION_DEMO`, `SIGNS_OPERATOR_TEMPLATE_NO_INDEPENDENT_RESCAN`, `ONE_SHARED_LOCAL_RPC_FOR_BOTH_COMPANIES`)와 `limitations` 배열로 표시합니다.

| # | 멘토 의견(요약) | 우리 판단 | 무엇을 했나 | 근거 위치 | 상태 |
|---|---|---|---|---|---|
| M1 | 3영역 구조는 타당하다. 다만 검증 쪽(릴리스당 1회, 실행 경로 밖)과 실행 쪽(매 호출, 사용자가 기다림)을 나눠 그리고, Gateway가 판정을 조회하는 경로를 보여 달라 | 수용 | 구조는 유지하고 그림을 두 흐름으로 다시 그림. Gateway A(운영사 API 조회)와 Gateway B(회사 B 자체 API → 체인 직접 조회)의 경로를 따로 표시 | [v2.1 §4.1](MCPShield_캡스톤_최종_마스터문서_v2.1.md), [ADR-005](adr-005-capstone-demo-path.md) | 반영 완료 |
| M2 | 실행 비용을 숫자로: (a) 호출당 추가 지연 (b) 격리·폐기 후 각 Gateway가 다음 호출을 막기까지 (c) 서버 다운·승인 만료 시 읽기/쓰기 처리. "93ms"는 스캔 시간이니 혼동 금지 | 수용 | 세 가지를 재는 하네스와 평가 스크립트 추가. (a) 직접 / A / B 각각 p50·p95·max 직접 0.24·0.45·0.55 ms, A 62.87·80.56·126.36 ms, B 61.69·79.76·80.09 ms(stdio Gateway 기준, 워밍업 뒤 세 대상 교차 호출. Gateway A 경로에는 장면 전환용 로컬 프록시 1홉이 더해지므로 A−B 차이를 운영사 비용으로 해석하지 않음) (b) 검증자가 체인에 직접 보낸 긴급 격리의 영수증 확인부터 이미 열린 세션의 첫 거부 호출까지 A·B 각각 126 ms(테스트는 거부 이유에 `QUARANTINED`가 들어 있음, 영수증 확인 뒤 시작한 호출의 허용 0건, 전송 전 예상 밖 실패 0건을 단언. 실측 거부 이유는 `RELEASE_QUARANTINED (QUARANTINED)`. 2-of-3 FAIL 폐기의 세션 전파는 미측정) (c) strict·balanced × 읽기·쓰기 처리표(실제로 끊은 운영사 엔드포인트를 상대로 하네스 프로세스에서 Gateway 라이브러리 `getAdmission`을 호출해 5개 경우 모두 단언: strict는 유효 캐시가 있어도 읽기·쓰기 차단, balanced는 유효 캐시로 읽기만 허용, 쓰기 캐시로도 쓰기 차단, 만료 캐시(+31초) 읽기 차단. 실제 Gateway A 세션은 다음 호출을 거부하고 세션 종료. B는 strict 도구 호출 성공만 확인, compose 스택에서는 아직 미확인. 서버는 정상인데 판정만 만료된 경우는 이 하네스가 확인하지 않음(기존 Gateway 테스트 범위, [ADR-006](adr-006-gateway-recheck-policy.md))). "93ms"가 스캐너 시간임을 문서에 명시 | [`consortium-scene.ts`](../tests/integration/consortium-scene.ts), [`evaluate-consortium-scene.ts`](../scripts/ops/evaluate-consortium-scene.ts), [ADR-006](adr-006-gateway-recheck-policy.md), [v2.1 §12.5·CAP2-504](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 로컬 구현·검증 (공식 측정 `f85f8e8`, Base Sepolia 미측정) |
| M3 | 보장 범위를 정확히: 다음 호출만 막는다, 이미 보낸 메일은 못 되돌린다, Gateway를 거치지 않은 MCP는 통제 밖이다 | 수용 | 세 문장을 README와 v2.1에 그대로 명시. 장면 5도 "이미 열린 세션의 다음 호출"이 막히기까지의 시간으로 정의. stdio Gateway가 호출을 거부하면 그 세션을 끝낸다는 점도 함께 명시 | [README 보장 범위](../README.md), [v2.1 §10.3·§19](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 |
| M4 | 실제 사고로 시작하라: 2025년 9월 npm `postmark-mcp` 업데이트가 보내는 메일을 몰래 공격자에게 숨은참조로 보냈다. 우리 메일 MCP 시나리오와 거의 같다 | 수용 | README 첫 화면과 v2.1 발표 계획(도입부)에 사례 반영. 실제 발표자료 개정은 아직 | [README](../README.md), [v2.1 §18](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 (발표자료 제작은 다음 단계) |
| M5 | 블록체인이 정당하려면 ① 서로 못 믿고 ② 중립 운영자가 없고 ③ 참여할 이유가 있어야 한다. ③이 비어 있다. 검증자가 없으면 Trust Plane도 없으니 "나중 문제"가 아니다 | 수용 | 검증자를 "MCP를 쓰는 회사 보안팀 컨소시엄"으로 정의. 참여 이유 = 검사 비용 분담 + 참여사만 조기 경보·판정 근거 원문 수령 | [ADR-003](adr-003-validator-consortium.md), [v2.1 §9.1](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 (설계 결정. 실제 회사의 참여 의향은 미검증 → 아래 질문 1) |
| M6 | 데모에서 팀이 검증자 3개를 돌리는 건 괜찮다. 하지만 운영에서 한 주체가 셋을 돌리면 "서명 3개 달린 중앙 DB"와 같고, 같은 스캐너·AI를 쓰면 함께 틀린다 | 수용 | 데모 키 3개는 팀 소유라고 명시. 참여사별로 AI 모델·검사 환경을 따로 줄 수 있는 기존 코드를 근거로 기록. 정적 규칙·sandbox 코드는 공유하므로 함께 틀릴 위험이 남는다고 명시 | [ADR-003](adr-003-validator-consortium.md), [`prepared-verification.ts:16-25, 46-59`](../apps/validator/src/prepared-verification.ts#L16-L59), [v2.1 §9.2](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 |
| M7 | 참여 동기 가설: (i) 기여해야 결과를 쓴다(VirusTotal 방식) (ii) 게시자·기업이 내는 검증 수수료를 서명한 검증자에게 분배 (iii) 평판·홍보 | 부분 수용 | (i)을 기본 모델로 채택. (ii)는 서명 건당 보상 문제(M8) 때문에 나중 확장으로 미룸. (iii)은 검사 비용을 계속 낼 단독 동기로는 약해 기본 모델로 채택하지 않고, 보조 동기로 로드맵에 둠 | [ADR-003](adr-003-validator-consortium.md), [v2.1 §20-6](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 (수수료 모델은 다음 단계) |
| M8 | 서명 건당 보상은 대충 서명할 유인이 된다. V2의 단독 긴급 격리는 다시 확인 가능한 증거만 받으니 이를 보상·벌점 근거로 삼아라. 체인엔 해시뿐이니 재현 가능한 증거 형식과 이의제기 절차가 필요하다 | 수용 | 서명 건당 보상은 하지 않고, 보상을 둔다면 다시 확인 가능한 증거에만 연결한다는 원칙을 기록. 컨트랙트가 단독 격리를 결정적 사유 3종·최대 1일로 제한함을 확인. 증거 형식·이의제기 절차는 로드맵 | [ADR-003](adr-003-validator-consortium.md), [`ReleaseRegistryV2.sol:181-185`](../contracts/src/ReleaseRegistryV2.sol#L181-L185) | 다음 단계 (원칙만 기록) |
| M9 | "중앙 DB는 숨길 수 있다"만으론 약하다(투명성 로그도 조용한 삭제를 막는다). 체인이 더해 주는 건 회사마다 다른 답을 주는 것 방지, 규칙 강제다. "단일 운영자 + 투명성 로그"와 나란히 비교하라 | 수용 | 세 방식(중앙 DB / 운영자+투명성 로그 / 블록체인) 비교표 작성. "투명성 로그와 클라이언트 검증을 제대로 갖추면 상당 부분 대체 가능"하다고 그대로 적고, 그래도 체인을 택한 이유를 정리 | [ADR-004](adr-004-blockchain-necessity-scene.md), [v2.1 §9.1·§19](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 |
| M10 | 기본 compose의 Gateway A/B는 같은 운영사 API를 쓰고 서명 검증 설정이 없어 응답을 그대로 믿는다. 서명 검증·조직 indexer·체인 직접 조회는 코드에 있지만 꺼져 있다. 최종 시연 경로를 정하고 그림과 설정을 맞춰라 | 수용 (사실 확인됨) | 최종 경로 결정: A → 운영사 API, B → 회사 B 자체 API, 둘 다 서명 `/v1` admission. 이 구성을 로컬 EVM 통합 테스트로 구현. compose는 아직 레거시 무서명 경로(아래 사실 확인 4) | [ADR-005](adr-005-capstone-demo-path.md), [`consortium-scene.test.ts`](../tests/integration/consortium-scene.test.ts), [`docker-compose.yml:25-30`](../docker-compose.yml#L25-L30) | 로컬 구현·검증 (compose 이전은 다음 단계) |
| M11 | 기본 배포는 V1이고 V2(검증자 교체·만료·긴급 격리)는 테스트 경로에서만 쓰인다. 최종에는 하나만 | 수용 · 확인 후 정정 | V2만 본선, V1은 레거시·확장으로 표시. 정정: V2 코드는 운영 모듈(`/v1` 관문, relayer, 검증자 CLI, Gateway 서명 모드)에도 들어가 있으나 환경변수로만 켜진다. 운영용 compose·시작 스크립트(`start:api` 등)는 V2를 켜지 않아, V2는 테스트·CI와 이번에 추가한 `evaluate:consortium-scene` 측정에서만 돈다 | [ADR-005](adr-005-capstone-demo-path.md), [v2.1 §2.4](MCPShield_캡스톤_최종_마스터문서_v2.1.md), [`docker-compose.yml:79`](../docker-compose.yml#L79) | 로컬 구현·검증 (장면 하네스는 V2만 사용, compose 기본 배포는 아직 V1 → 다음 단계) |
| M12 | owner 하나가 릴리스 등록·정책 관리·검증자 교체(1일 타임락)를 맡고, 검증자 비활성화는 즉시라 기존 VERIFIED를 모두 만료시킬 수 있다. MVP 단일 관리자는 괜찮지만 운영 멀티시그와 비상 절차 계획을 밝혀라 | 수용 · 확인 후 정정 | owner가 할 수 있는 것/없는 것을 코드 기준으로 정리. MVP는 단일 배포 키임을 공개. 운영안: 컨소시엄 멀티시그(예: Safe 3-of-5)를 관리자로 배포(owner가 바뀔 수 없어 재배포 필요), 즉시 권한(비활성화·정책 폐기·등록)의 타임락 또는 멀티시그 정족수는 다음 컨트랙트 버전, 비상 절차는 계획으로 기록. 교체는 "owner가 예약만 하고 실행은 누구나"로 정정(사실 확인 1) | [ADR-007](adr-007-registry-owner-governance.md), [`ReleaseRegistryV2.sol:29-48`](../contracts/src/ReleaseRegistryV2.sol#L29-L48), [v2.1 §9.5](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 (문서) · 멀티시그·타임락 구현은 다음 단계 |
| M13 | 데모 아이디어: 운영사 API가 꺼지거나 거짓말해도 체인을 읽는 회사 B의 Gateway는 폐기 버전을 막는다 | 수용 · 확인 후 정정 | "운영사 DB 조작"은 거짓 ALLOW를 만들지 못함을 코드로 확인(사실 확인 3) → 장면을 **운영사 admission 서명 키 장악**과 **운영사 장애**로 바꿔 구현. 장악: 폐기를 본 적 없는 새 A는 운영사 키로 서명된 위조 ALLOW를 받아들이고(대조군), 앞 장면에서 폐기를 기록해 둔 A는 로컬 기록으로 거부, B는 REVOKED로 차단, 체인은 계속 REVOKED(세 결과 모두 테스트가 단언. API 프로세스 전체 장악 시의 서비스 거부 위험은 사실 확인 3). 장애: A 실패-닫힘(실행 중 세션의 다음 호출 거부 후 세션 종료), B 계속 동작. 폐기 장면에서는 두 Gateway 모두 `run` 명령에서 후보 실행 전에 거부. 새 P0 행 CAP2-308로 고정 | [ADR-004](adr-004-blockchain-necessity-scene.md), [`consortium-scene.ts`](../tests/integration/consortium-scene.ts), [`consortium-scene.test.ts`](../tests/integration/consortium-scene.test.ts), [v2.1 §5.4](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 로컬 구현·검증 (화면·compose 연출은 다음 단계) |
| M14 | V1/V2, 여러 admission 경로, break-glass, 영수증 앵커링, OCI/Streamable HTTP, PostgreSQL 전환이 함께 있다. 지우지 말고 최종 경로 하나를 고정하고 나머지는 "확장"으로 표시하라 | 수용 | 본선 경로 표와 확장 표를 만들어 고정. 코드는 삭제하지 않음 | [v2.1 §2.4](MCPShield_캡스톤_최종_마스터문서_v2.1.md), [ADR-005](adr-005-capstone-demo-path.md) | 반영 완료 |
| M15 | 같은 예제를 반복한 결과는 재현성이지 일반 탐지 성능이 아니다. 정적 규칙·AI·sandbox가 각각 무엇을 잡았는지 따로 보여라 | 수용 | 반복 픽스처 수치는 재현성으로만 표기하기로 함. 계층별 결과는 별도 holdout 표본으로 실행한 뒤 따로 보고. 이번 장면 테스트는 REPORT FIXTURE 대역을 쓰므로 탐지 성능의 근거가 아님 | [v2.1 §12.2·CAP2-502](MCPShield_캡스톤_최종_마스터문서_v2.1.md), [evaluation.md](evaluation.md) | 다음 단계 |
| M16 | GitHub 기본 브랜치 `main`이 9월 5일 상태라 심사자가 최신 README·코드를 못 본다 | 수용 | 2026-10-11 기본 브랜치를 `master/main`으로 변경 | [README](../README.md), [v2.1 §14.1](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 |
| M17 | MCP 서버 목록 사이트에 같은 이름의 스캐너가 여럿 있다. 이름은 유지해도 되지만 차별점을 한 줄로 밝혀라 | 수용 | "업데이트마다 재검증 · 실행 전 강제 · 다기관 판정" 한 줄을 README 첫 화면과 v2.1에 추가 | [README](../README.md), [v2.1 §1.2·§19](MCPShield_캡스톤_최종_마스터문서_v2.1.md) | 반영 완료 |
| M18 | 다음(4회차)에는 컨트랙트 세부: 가스비, 키 교체 구현, 정책 버전 관리 | 수용 | 준비 항목과 지금 코드에서 확인한 사실을 정리(아래 "4회차 준비") | 이 문서 [4회차 준비](#4회차-준비) | 다음 단계 |
| M19 | 팀 결정 5개를 ADR로: 최종 데모 경로, 재검사 정책, 검증자 설계, owner 권한 운영, 블록체인 필요 조건 한 장 | 수용 | ADR 5개 작성: 검증자 설계 [ADR-003](adr-003-validator-consortium.md), 블록체인 필요 장면 [ADR-004](adr-004-blockchain-necessity-scene.md), 최종 데모 경로 [ADR-005](adr-005-capstone-demo-path.md), 재검사 정책 [ADR-006](adr-006-gateway-recheck-policy.md), owner 권한 운영 [ADR-007](adr-007-registry-owner-governance.md) | 왼쪽 링크 | 반영 완료 |

재검사 정책(ADR-006) 요약: 도구 호출마다 승인 상태를 다시 확인하는 strict를 기본으로 유지합니다. 판정을 몇 초 재사용할지는 측정 결과를 보고 정합니다. 재사용 창은 곧 "폐기된 릴리스가 계속 실행될 수 있는 최대 시간"이므로 정하게 되면 그 값을 함께 보고합니다. 운영사 장애 때(조직 indexer·직접 RPC 폴백을 켜지 않은 본선 구성 기준) strict는 읽기·쓰기 모두 막고, balanced는 아직 유효한 서명 캐시가 있는 동안 읽기 전용 호출만 허용하며 캐시로는 쓰기를 허용하지 않습니다.

---

## 멘토 의견 중 사실 확인 결과

의견을 반영하기 전에 해당 부분 코드를 직접 확인했습니다. 대부분 말씀하신 그대로였고, 세부가 다르거나 더 알게 된 점을 아래에 적습니다. 줄 번호는 이 브랜치 기준입니다.

### 1. 검증자 교체: owner는 "예약"만 하고, 실행은 누구나 할 수 있다 (정정)

- owner는 `scheduleRotation`으로 다음 검증자 집합을 **예약만** 합니다([`ReleaseRegistryV2.sol:29`](../contracts/src/ReleaseRegistryV2.sol#L29)).
- 대기 시간은 **1일로 고정**되어 있습니다([`:32`](../contracts/src/ReleaseRegistryV2.sol#L32)). 1일이 지나면 owner가 아니어도 **누구나** `rotate()`를 호출해 교체를 실행할 수 있습니다([`:35-36`](../contracts/src/ReleaseRegistryV2.sol#L35-L36), owner 검사 없음).
- 덧붙여 알게 된 점: 예약 취소 함수가 없고 다시 예약하면 덮어씁니다. 예약 사실과 발효 시각은 이벤트로 공개되지만, 새 검증자 주소는 private 변수에만 있고 이벤트에 실리지 않습니다([`:8`](../contracts/src/ReleaseRegistryV2.sol#L8), [`:11`](../contracts/src/ReleaseRegistryV2.sol#L11), [`:33`](../contracts/src/ReleaseRegistryV2.sol#L33)). 다만 `scheduleRotation` 거래의 입력값(calldata)으로는 누구나 확인할 수 있습니다([`:29`](../contracts/src/ReleaseRegistryV2.sol#L29)). 문제는 지금 이를 감시하는 코드가 없어 1일 대기 동안 놓치기 쉽다는 점입니다. 4회차 키 교체 주제로 가져갑니다.

### 2. 검증자 비활성화: 즉시 적용되고 모든 VERIFIED를 만료시킨다. 다만 실패-닫힘이지 거짓 ALLOW는 아니다 (확인, 보강)

- `disable`은 owner 전용이고 지연이 없으며, 전역 검증자 집합 버전을 1 올립니다([`:43-48`](../contracts/src/ReleaseRegistryV2.sol#L43-L48)).
- `getDecision`은 판정 당시 버전이 현재 버전과 같을 때만 VERIFIED를 돌려주고([`:198-200`](../contracts/src/ReleaseRegistryV2.sol#L198-L200)), 다르면 EXPIRED로 읽습니다([`:201-203`](../contracts/src/ReleaseRegistryV2.sol#L201-L203)). 그래서 **비활성화 한 번으로 모든 릴리스의 VERIFIED가 동시에 만료**됩니다. 기존 테스트에서도 확인됩니다([`tests/contracts/release-registry-v2.test.ts:44-46`](../tests/contracts/release-registry-v2.test.ts#L44-L46)).
- 이 결과는 정상 도구까지 멈추는 **서비스 거부(실패-닫힘)** 이지, 위험한 버전을 허용하는 거짓 ALLOW가 아닙니다. REVOKED는 한 방향으로만 바뀌고 되돌리는 함수가 없습니다([`:161`](../contracts/src/ReleaseRegistryV2.sol#L161), [`:196`](../contracts/src/ReleaseRegistryV2.sol#L196)). 즉 **owner 키가 장악되어도 REVOKED를 VERIFIED로 바꿀 수는 없습니다.** 다만 1일 지연 뒤에는 owner가 예약한 검증자 교체로 공격자 키를 검증자로 넣어, REVOKED가 아닌 릴리스에 거짓 VERIFIED를 만들 수 있습니다. 이때는 공개된 교체 예약 이벤트와 Gateway가 고정한 검증자 집합 버전이 방어선입니다([ADR-007](adr-007-registry-owner-governance.md)).
- 주의할 점: 검증자 2명만 비활성화해도 활성 키가 1개만 남아 다음 교체(최소 1일)까지 2-of-3 정족수를 채울 수 없습니다. 비상 절차 설계에서 고려합니다([ADR-007](adr-007-registry-owner-governance.md)).

### 3. 운영사 API는 요청마다 체인을 다시 읽는다. 그래서 DB 조작으로는 ALLOW를 만들 수 없다 (처음 장면 구상을 정정)

- 처음에는 "운영사 DB를 조작하면 운영사만 믿는 Gateway A가 속는다"는 장면을 구상했습니다. 코드를 확인하니 성립하지 않습니다.
- `/v1/admission/check`는 DB에서 릴리스·정책 문서만 읽고([`apps/api/src/control-plane.ts:288`](../apps/api/src/control-plane.ts#L288)), 상태는 매 요청 체인 조회 결과로 정합니다([`:291`](../apps/api/src/control-plane.ts#L291)). ALLOW는 체인(EVM)에서 읽은 VERIFIED일 때만 나오며([`:296`](../apps/api/src/control-plane.ts#L296)), 서명된 응답에는 조회한 블록 번호와 블록 해시가 들어갑니다([`:309-319`](../apps/api/src/control-plane.ts#L309-L319)). 체인 조회기는 체인에 등록된 릴리스 신원과 DB 기록이 같은지도 대조합니다([`packages/contracts-sdk/src/v2-chain-reader.mjs:62-66`](../packages/contracts-sdk/src/v2-chain-reader.mjs#L62-L66)).
- 그래서 DB를 바꾸면 DIGEST_MISMATCH, POLICY_MISMATCH, 조회 불가 같은 **BLOCK**만 나옵니다. 기존 테스트도 같은 성질을 보여 줍니다. DB 상태가 UNVERIFIED여도 체인 조회가 VERIFIED면 ALLOW가 나옵니다([`tests/api/control-plane.test.ts:25, 38-39, 65-66`](../tests/api/control-plane.test.ts#L25-L66)). API가 DB가 아니라 체인을 따른다는 뜻입니다.
- 참고: 체인 조회 설정(`CONTROL_V2_RPC_URLS`)이 없으면 `/v1`은 항상 LOCAL_DEMO 상태로 BLOCK합니다([`apps/api/src/control-config.ts:57-59`](../apps/api/src/control-config.ts#L57-L59), [`control-plane.ts:290`](../apps/api/src/control-plane.ts#L290)).
- 그래서 현실적인 위협을 **"운영사의 admission 서명 권한 장악"** 으로 바꿨습니다. Gateway A는 운영사 Ed25519 서명과 응답 형식·문맥만 확인하고([`apps/gateway/src/signed-admission.mjs:82-101`](../apps/gateway/src/signed-admission.mjs#L82-L101)), 운영사 API가 응답하는 동안에는 체인을 스스로 다시 읽지 않습니다(직접 RPC 조회는 API가 응답하지 않을 때만 쓰는 폴백, [`:202`](../apps/gateway/src/signed-admission.mjs#L202), [`:226-237`](../apps/gateway/src/signed-admission.mjs#L226-L237)). 그래서 자기가 직접 보지 못한 폐기에 대해서는 운영사 키로 서명된 거짓 VERIFIED를 받아들입니다. 이미 본 폐기는 같은 Gateway 프로세스 안에서는 메모리 기록으로 거부하고, 프로세스를 새로 띄운 뒤(stdio 세션·`inspect`·`run`은 매번 새 프로세스)에는 로컬 폐기 기록 파일(`MCPSHIELD_ADMISSION_CACHE_FILE`)을 켜 둔 경우에만 거부합니다([`:243-246`](../apps/gateway/src/signed-admission.mjs#L243-L246)). 즉 운영사가 장악된 동안 일어난 폐기나 새로 설치한 Gateway에는 이 기록이 소용없습니다. Gateway B는 회사 B 자체 API가 체인을 읽으므로 막습니다. 이 차이가 장면 4이며, 장면 4는 기록 없는 A(속음)·기록 있는 A(거부)·B(거부)를 모두 보여 줍니다. 장면 4가 실제로 재현하는 것은 **admission 서명 키 장악**입니다.
- **API 프로세스 전체가 장악되면 더 나쁩니다.** MVP에서는 릴리스 등록·정책 게시가 owner 전용이라, 운영사 API가 쥔 relayer 키가 곧 세 레지스트리의 owner 키입니다([`contracts/scripts/deploy-v2.ts:20-23`](../contracts/scripts/deploy-v2.ts#L20-L23), [`apps/api/src/chain-outbox.ts:52-54`](../apps/api/src/chain-outbox.ts#L52-L54), [`apps/api/src/control-config.ts:60`](../apps/api/src/control-config.ts#L60)). 이 경우에도 REVOKED→VERIFIED는 불가능하고 B는 REVOKED를 계속 막지만, 공격자가 검증자 비활성화·정책 폐지로 정상 릴리스까지 만료시켜 A·B 모두 실패-닫힘으로 멈출 수 있습니다(서비스 거부). 운영에서는 owner(멀티시그)와 relayer 키를 분리합니다([ADR-007](adr-007-registry-owner-governance.md)).
- 정직하게 덧붙이면, 이 이점은 **체인을 직접(또는 자기 노드로) 읽는 회사**에만 생깁니다. 데모에서는 두 회사가 같은 로컬 RPC를 쓰며, 운영 환경에서는 회사마다 자기 노드나 여러 RPC 공급자를 써야 RPC가 새로운 신뢰 지점이 되지 않습니다.

### 4. 기본 compose의 두 Gateway는 레거시 무서명 경로를 쓴다 (확인)

- compose의 공통 Gateway 설정은 두 Gateway 모두 같은 backend를 API 주소로 쓰고([`docker-compose.yml:27`](../docker-compose.yml#L27)), `MCPSHIELD_POLICY_HASH`를 설정하지 않습니다([`:25-30`](../docker-compose.yml#L25-L30)). gateway-a/b는 이름과 증거 파일만 다릅니다([`:197-216`](../docker-compose.yml#L197-L216)).
- Gateway는 `MCPSHIELD_POLICY_HASH`가 있을 때만 서명 admission을 쓰고([`apps/gateway/src/index.mjs:83-85`](../apps/gateway/src/index.mjs#L83-L85)), 없으면 레거시 `/api/admission/check`에서 서명 없는 응답을 받습니다([`:87`](../apps/gateway/src/index.mjs#L87)). balanced 모드도 서명 경로에서만 허용되므로([`:86`](../apps/gateway/src/index.mjs#L86)) 지금 compose 스택에서는 읽기/쓰기 처리 차이가 나타나지 않습니다.
- 함께 확인한 것: compose는 V1을 배포합니다([`docker-compose.yml:79`](../docker-compose.yml#L79)의 `npm run chain:deploy` → `contracts/scripts/deploy.ts`, 기본 컨트랙트 `ReleaseRegistry`는 [`contracts/scripts/compile.ts:12`](../contracts/scripts/compile.ts#L12)). backend 헬스체크도 V1 기준입니다([`docker-compose.yml:115`](../docker-compose.yml#L115)). compose를 V2 두 회사 구성으로 옮길 때 함께 고칩니다.

### 5. 그 밖에 확인한 것

- **"93ms"**: [evaluation.md](evaluation.md) 50행의 값은 2026-09-04 스냅샷(3행)에서 안전 픽스처를 **스캔하는 데 걸린 시간**입니다(evaluation.md 원문의 "latency"는 security benchmark의 스캐너 실행 시간을 뜻합니다). Gateway 지연이 아닙니다. 기존 측정의 `receiptToNextCheckBlockedMs`(50.375ms, [`admission-smoke-100-8569025-2026-10-01.json`](../benchmarks/results/admission-smoke-100-8569025-2026-10-01.json))도 폐기 전파 시간이 아니라 영수증을 받은 직후 1회 검사한 시간입니다. 그래서 M2의 (a)(b)를 새로 잽니다.
- **단독 긴급 격리**: 사유가 `CANARY_EXFILTRATION`, `HOST_ESCAPE_ATTEMPT`, `DIGEST_MISMATCH` 중 하나일 때만 허용되고([`ReleaseRegistryV2.sol:184`](../contracts/src/ReleaseRegistryV2.sol#L184)), 기간은 최대 1일입니다([`:185`](../contracts/src/ReleaseRegistryV2.sol#L185)). 말씀하신 그대로입니다.
- **owner의 범위**: 릴리스 등록이 owner 전용인 것은 맞습니다([`:116-117`](../contracts/src/ReleaseRegistryV2.sol#L116-L117)). 다만 owner 자리는 세 컨트랙트에 따로 있고 모두 바꿀 수 없습니다([`:5`](../contracts/src/ReleaseRegistryV2.sol#L5), [`:52`](../contracts/src/ReleaseRegistryV2.sol#L52), [`:91`](../contracts/src/ReleaseRegistryV2.sol#L91)). 배포 스크립트에서 별도 관리자(`V2_GOVERNANCE_ADMIN`)를 지정하면 검증자·정책 레지스트리의 owner는 그 주소가 되지만, ReleaseRegistryV2의 owner는 배포 지갑으로 고정됩니다([`contracts/scripts/deploy-v2.ts:20-23`](../contracts/scripts/deploy-v2.ts#L20-L23)). 멀티시그로 바꾸려면 배포 스크립트 수정과 재배포가 필요하고, 운영사 relayer가 보내던 정책 게시·폐지·릴리스 등록([`apps/api/src/chain-outbox.ts:52-54`](../apps/api/src/chain-outbox.ts#L52-L54))도 멀티시그 제안 흐름으로 바꿔야 합니다. 그대로 두면 이 거래들은 `ONLY_OWNER`로 실패합니다.

---

## 4회차 준비

4회차(컨트랙트 세부)에 가져갈 내용입니다. 지금 코드에서 확인한 사실과, 그때까지 만들어 올 것을 나눴습니다.

### 가스비

- **이미 있는 값(로컬 EVM).** 기존 측정([`admission-smoke-100-8569025-2026-10-01.json`](../benchmarks/results/admission-smoke-100-8569025-2026-10-01.json), Ganache, 2026-10-01)의 `gasUsed`입니다. 그 뒤로 V2 컨트랙트 코드는 바뀌지 않았습니다. 이것은 gas **사용량**이고 실제 비용(원화·ETH)이 아닙니다.

  | 거래 | gasUsed (로컬) |
  |---|---|
  | 정책 게시 | 68,663 (1건) |
  | 릴리스 등록 | 137,335~137,347 (4건) |
  | PASS 서명 제출 | 137,088~182,283 (8건) |
  | FAIL 서명 제출 | 136,745~152,818 (2건) |
  | 긴급 격리 | 99,505 (1건) |

- **가져올 것.**
  - 릴리스 1건의 생애 비용표: 등록 + PASS 2건(승인), 또는 격리 + FAIL 2건(폐기).
  - 아직 재지 않은 거래(교체 예약, 교체 실행, 비활성화, 정책 폐기)의 로컬 gasUsed는 4회차 전에 측정합니다.
  - 교체·비활성화 1회의 숨은 비용: 모든 VERIFIED가 만료되므로(사실 확인 2) 활성 릴리스마다 PASS 서명을 다시 2건씩 내야 합니다. 활성 릴리스 수에 따라 비용이 어떻게 늘어나는지 표로 보여 드리겠습니다.
  - Base Sepolia: 배포 키가 준비되면 같은 거래를 보내 영수증 기준 실제 수수료와 확정 대기 시간을 기록합니다. Base는 L2 실행 수수료에 L1 데이터 수수료가 더해지므로 둘을 나눠 적습니다.
  - 누가 내는가: 지금은 검증자가 EIP-712 서명만 하고 거래는 운영사 relayer가 대신 제출하는 구조입니다([`apps/api/src/control-config.ts:60`](../apps/api/src/control-config.ts#L60), [`apps/api/src/chain-outbox.ts:55`](../apps/api/src/chain-outbox.ts#L55)). 장면 5처럼 검증자가 직접 체인에 보낼 수도 있습니다. 컨소시엄에서 가스비를 어떻게 나눌지 안을 함께 가져오겠습니다.

### 키 교체 구현

키는 세 종류이고, 각각 교체 방식이 다릅니다.

| 키 | 지금 코드 | 교체할 때 생기는 일 |
|---|---|---|
| 검증자 서명 키(체인의 검증자 집합) | owner 예약 → 1일 고정 대기 → 누구나 실행. 유출 시 owner가 즉시 비활성화 | 버전이 올라가 모든 VERIFIED 만료([`:39`](../contracts/src/ReleaseRegistryV2.sol#L39), [`:199`](../contracts/src/ReleaseRegistryV2.sol#L199)). 새 집합이 다시 서명해야 하고, Gateway가 고정해 둔 검증자 집합 버전도 바꿔야 함([`signed-admission.mjs:88`](../apps/gateway/src/signed-admission.mjs#L88)) |
| 회사별 admission 서명 키(Ed25519) | Gateway는 키 ID와 공개키 **한 개**만 고정([`signed-admission.mjs:86`](../apps/gateway/src/signed-admission.mjs#L86), [`:110`](../apps/gateway/src/signed-admission.mjs#L110)) | 겹치는 기간 없이 Gateway 설정을 바꿔야 함 |
| owner(관리자) 키 | 세 컨트랙트 모두 바꿀 수 없음 | 재배포 필요 |

가져올 것:

- 로컬 EVM 교체 리허설 테스트: 정상 교체, 그리고 "키 유출 → 즉시 비활성화 → 새 집합 예약 → 1일 뒤 교체 → 재서명" 흐름. 그동안 정상 도구가 막혀 있는 시간과 재서명 gas를 잽니다(4회차 전 측정 예정).
- 컨트랙트 개선안 초안(구현 아님): 예약 내용을 이벤트로 공개, 예약 취소, 멀티시그 관리자.
- Gateway가 admission 키 두 개를 잠시 함께 받아 주는 교체 기간 설정안(구현 아님).
- owner 키 교체(재배포) 때 기존 컨트랙트의 REVOKED 기록을 어떻게 이어 갈지에 대한 안. 지금은 자동으로 옮겨지지 않으며 아직 정하지 않았습니다([ADR-007](adr-007-registry-owner-governance.md) 미해결 항목).

### 정책 버전 관리

- **지금 코드의 사실.** 정책은 해시 단위로 게시되고, 게시 후에는 내용을 바꿀 수 없습니다([`ReleaseRegistryV2.sol:61`](../contracts/src/ReleaseRegistryV2.sol#L61)). 폐기(deprecate)는 즉시·일방향입니다([`:65-69`](../contracts/src/ReleaseRegistryV2.sol#L65-L69)). 판정은 (릴리스, 정책 해시) 쌍마다 따로 저장됩니다([`:95`](../contracts/src/ReleaseRegistryV2.sol#L95)). 정책을 폐기하면 그 정책으로 받은 VERIFIED가 만료되고([`:199-203`](../contracts/src/ReleaseRegistryV2.sol#L199-L203)), 그 정책으로는 새 서명·격리도 받지 않습니다([`:137`](../contracts/src/ReleaseRegistryV2.sol#L137), [`:183`](../contracts/src/ReleaseRegistryV2.sol#L183)). Gateway는 정책 해시 하나를 고정합니다([`signed-admission.mjs:87`](../apps/gateway/src/signed-admission.mjs#L87)).
- **가져올 것.**
  - 무중단 전환 순서안: 새 정책 게시 → 새 정책으로 재검사·서명 → Gateway 고정값 교체 → 옛 정책 폐기. 이 순서를 로컬에서 돌린 결과(차단 시간 포함, 4회차 전 측정 예정)와, 순서를 어겼을 때 어떻게 실패-닫힘이 되는지.
  - 정책 문서의 버전 표기 규칙과 "누가 정책 변경을 승인하는가"(멀티시그, [ADR-007](adr-007-registry-owner-governance.md)).

---

## 피드백 부탁드리는 질문

1. **컨소시엄 참여 동기가 현실적인가요?** "검증에 참여한 회사만 조기 경보와 판정 근거 원문을 받는다"는 조건이, 기업 보안팀이 검사 비용을 나눠 낼 만한 이유가 될까요? 설득력을 가지려면 최소 몇 곳이, 어떤 성격의 회사가 참여해야 한다고 보시는지 궁금합니다.
2. **운영사 장악 장면이 설득력 있나요?** "운영사 DB 조작"은 코드상 거짓 ALLOW를 만들지 못해 "운영사 서명 권한 장악"으로 바꿨습니다. 이 위협 가정이 심사에서 받아들여질지, 아니면 "운영사 장애" 장면을 앞에 세우는 편이 나을지 의견을 듣고 싶습니다.
3. **재검사·전파 시간은 어느 정도까지 허용될까요?** 지금은 매 호출 재검사를 기본으로 둡니다. 측정 뒤 판정 재사용 창을 둔다면, 폐기된 릴리스가 계속 실행될 수 있는 시간을 몇 초까지 받아들일 만하다고 보시나요? 메일 발송 같은 쓰기 도구는 0초여야 한다고 보시는지도 궁금합니다.
4. **멀티시그 거버넌스의 최소 기준은 어디까지일까요?** 운영 시에는 컨소시엄 멀티시그를 관리자로 두고, 정책 폐기·릴리스 등록 같은 즉시 권한에 타임락을 넣으려 합니다. 그런데 키 유출 대응용 비활성화는 즉시 실행되어야 해서 타임락과 충돌합니다. 캡스톤 단계에서 어디까지 구현하고 어디부터 설계로 남겨도 되는지 기준을 듣고 싶습니다.
