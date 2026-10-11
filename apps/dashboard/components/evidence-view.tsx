import React from "react";

type Json = Record<string, unknown>;
const object = (value: unknown): Json => value && typeof value === "object" && !Array.isArray(value) ? value as Json : {};
const text = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : "—";
const rows = (value: unknown) => Array.isArray(value) ? value.map(object) : [];

export function EvidenceView({ evidence }: { evidence: unknown }) {
  const data = object(evidence);
  if (data.verification === "API_VERIFIED") return <div className="ops-message"><b>API가 증거 루트를 검증함</b><p>파일 {text(data.leafCount)}개 · {text(data.checkedAt)}</p><code>{text(data.root)}</code><p>브라우저 독립 검증이 아닙니다. 준비 실행의 원문 도구·파일·호출 인자는 화면으로 전달하지 않습니다.</p></div>;
  const bundle = object(data.bundle);
  const files = object(bundle.files);
  const document = (path: string): Json => {
    try { return typeof files[path] === "string" ? object(JSON.parse(files[path])) : {}; } catch { return {}; }
  };
  const report = document("report.json");
  const sbom = document("static/sbom.cdx.json");
  const diff = document("static/package-diff.json");
  const semantic = document("semantic/model-output.json");
  const runtime = document("sandbox/mcp.json");
  const sbomSource = rows(object(sbom.metadata).properties).find((item) => item.name === "mcpshield:dependency-completeness")?.value;
  if (!Object.keys(files).length) return <pre className="ops-json">{JSON.stringify(evidence, null, 2)}</pre>;

  return <div className="ops-evidence">
    <div className="ops-message"><b>{text(report.scanStatus)}</b> · 분석 범위 {text(report.scope)} · 런타임 MCP {runtime.complete === true ? "격리 실행 수집 완료" : "수집 미완료"}<br />검사 작업의 완료 여부와 릴리스 실행 허가는 별도로 확인해야 합니다.</div>
    <dl className="ops-facts"><div><dt>API에서 검증한 증거 root</dt><dd>{text(data.reportRoot)}</dd></div><div><dt>AI 분석 제공자</dt><dd>{text(semantic.provider)}</dd></div></dl>
    <h3>발견 사항</h3><div className="ops-table-wrap"><table><thead><tr><th>심각도</th><th>발견 사항</th><th>근거 유형</th><th>내용</th></tr></thead><tbody>{rows(report.findings).map((finding, index) => <tr key={index}><td>{text(finding.severity)}</td><td>{text(finding.code)}</td><td>{finding.deterministic === true ? "결정론적 근거" : "검토 필요"}</td><td className="ops-wrap">{text(finding.message)}</td></tr>)}</tbody></table></div>
    <h3>구성요소 목록 · SBOM</h3><p>{text(sbom.bomFormat)} {text(sbom.specVersion)} · {sbomSource === "lockfile" ? "잠금 파일에서 추출" : "선언 목록 기준 · 전체 의존성은 확정되지 않음"}</p><div className="ops-table-wrap"><table><thead><tr><th>패키지</th><th>버전</th><th>범위</th><th>식별자</th></tr></thead><tbody>{rows(sbom.components).map((component, index) => <tr key={index}><td>{text(component.name)}</td><td>{text(component.version)}</td><td>{text(component.scope)}</td><td className="ops-wrap"><code>{text(component.purl)}</code></td></tr>)}</tbody></table>{!rows(sbom.components).length && <p className="ops-empty">추출된 의존성이 없습니다. 이 결과만으로 외부 의존성이 없다고 단정하지 않습니다.</p>}</div>
    <h3>버전 변경 내역</h3><p>{diff.hasBaseline === true ? "이전 버전과 비교한 도구·의존성·외부 전송 목적지 변경입니다." : "비교할 이전 버전이 지정되지 않았습니다. 아래 항목은 업데이트 비교 증거가 아닙니다."}</p><div className="ops-table-wrap"><table><thead><tr><th>구분</th><th>항목</th><th>변경</th></tr></thead><tbody>{["tools", "dependencies", "installScripts", "egress"].flatMap((kind) => rows(diff[kind]).map((item, index) => <tr key={`${kind}-${index}`}><td>{kind}</td><td>{text(item.name)}</td><td className="ops-wrap">{kind === "tools" ? `${text(item.change)} · ${Array.isArray(item.fields) ? item.fields.map(text).join(", ") : ""}` : `${text(item.before ?? item.beforeHash)} → ${text(item.after ?? item.afterHash)}`}</td></tr>))}</tbody></table></div>
    <h3>격리된 MCP 실행 증거</h3>{runtime.complete === true ? <><p>프로토콜 {text(runtime.protocolVersion)} · 도구 목록 {text(runtime.pages)}페이지 수집</p><div className="ops-table-wrap"><table><thead><tr><th>호출한 도구</th><th>결과</th><th>응답 내용 해시</th></tr></thead><tbody>{rows(runtime.callResults).map((call, index) => <tr key={index}><td>{text(call.name)}</td><td>{call.isError === true ? "오류" : "응답 수집"}</td><td className="ops-wrap">{text(call.contentHash)}</td></tr>)}</tbody></table></div></> : <p className="ops-empty">이 증거에는 완료된 격리 MCP 실행 결과가 없습니다. 정적 분석 결과를 실제 실행 검증으로 표시하지 않습니다.</p>}
    <details><summary>원문 증거 문서와 Merkle proof</summary>{Object.entries(files).map(([path, content]) => <details key={path}><summary>{path}</summary><pre>{typeof content === "string" ? content : "문서 형식 오류"}</pre></details>)}<pre>{JSON.stringify(bundle.manifest, null, 2)}</pre></details>
  </div>;
}
