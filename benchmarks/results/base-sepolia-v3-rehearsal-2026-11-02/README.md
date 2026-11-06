# Base Sepolia 리허설 (2026-11-02, 버리는 배포)

발표에 쓰는 배포는 [`deployments/base-sepolia-v3.json`](../../../deployments/base-sepolia-v3.json)(끝자리 F604) 그대로입니다. 이 폴더는 2026-11-02 새벽의 시연 구성을 새 배포([`deployment.json`](deployment.json), ReleaseRegistryV3 `0x2bB5e9c5527d7f7B679cBddedb3223AB34b510f0`)에서 처음부터 끝까지 한 번 돌린 기록입니다. 같은 날 최종 시연 구성은 A사 증인을 GPT-6 Luna로 바꿨습니다(40개 평가 결과에 따른 결정). Gateway 장면 결과는 AI 증인과 무관합니다.

- **실행:** `npm run demo:v3 -- --base-sepolia --deploy --seed --no-dashboard --ai A=openai:gpt-6.1-terra --ai C=gemini:gemini-3.5-flash`, 이어서 `npm run demo:gateways -- --stack <데이터 폴더>`.
- **구성:** 검증자 A사는 GPT-6.1 Terra를 AI 증인으로 씁니다. B사는 규칙과 시험 환경만 씁니다. C사는 Gemini 3.5 Flash 증인을 쓰고 긴급 격리를 맡습니다. 표는 운영사 중계 계정이 제출했고, 긴급 격리는 C사 지갑이 직접 보냈습니다. 검증자 키 3개는 팀이 운영합니다(`SINGLE_INSTITUTION_DEMO`).
- **결과:** 1.0.0은 세 곳 모두 PASS를 내서 VERIFIED가 됐습니다. 1.0.1은 C사가 먼저 긴급 격리했고, 세 곳 모두 FAIL을 내서 REVOKED가 됐습니다. AI 증인은 네 번 모두 응답했습니다.
- **거래:** 13건(배포 3 · 정책 게시 1 · 등록 2 · 표 6 · 긴급 격리 1). gas 합계는 5,023,105, 수수료는 0.000030139 ETH입니다. 각 거래는 [`transactions.json`](transactions.json)에 Basescan 링크와 함께 있습니다.
- **증거:** 표 6건의 `evidenceHash`는 [`evidence/`](evidence/)에 있는 각 검증자 증거 파일의 sha256과 같습니다(`transactions.json`의 `votesMatchEvidence`).
- **두 회사 Gateway 장면** ([`gateway-scene.json`](gateway-scene.json), 공개 RPC `sepolia.base.org`, 표본 20회):
  - 호출할 때마다 판정을 다시 받아도 p50은 A사 1,098 ms, B사 1,092 ms였습니다. Gateway 없이 직접 호출하면 0.3 ms입니다.
  - 운영사 연결을 끊으면 A사는 엄격 모드라 멈추고, B사는 계속 씁니다.
  - 1.0.1은 두 회사 모두 프로세스를 띄우기 전에 거부했습니다(exit 3).
