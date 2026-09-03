# MCPShield Agent Rules

모든 작업자는 `WORKTREE_COLLABORATION_RULES.md`를 먼저 읽고 따른다.

- Main은 공통 인터페이스, 병합, 통합 검증을 소유한다.
- 구현 담당자는 자신에게 배정된 경로만 수정한다.
- Reviewer는 어떤 파일도 수정하거나 커밋하지 않는다.
- 공통 스키마 변경은 Main 승인 없이 수행하지 않는다.
- 실제 개인정보, 외부 공격 서버, 실제 비밀키를 사용하지 않는다.
- mock, replay, live 결과를 명확히 구분한다.
