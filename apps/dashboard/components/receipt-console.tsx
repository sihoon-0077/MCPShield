import React, { useRef, useState, type FormEvent } from "react";
import { controlApi } from "../lib/control-client";
import { validReceiptWriter, type ReceiptEvidenceSummary } from "../lib/receipt-summary";

export type ReceiptRecord = {
  ledgerKey: string; writer?: string; batchId?: string; root?: string; count?: number; fromSequence?: number; toSequence?: number;
  assurance: string; queueStatus: string | null; txHash: string | null; errorCode: string | null;
  confirmations: number; requiredConfirmations: number; chainId: number; registryAddress: string;
  observedAt?: string; observedBlock?: number; observedBlockHash?: string; createdAt: string; sources?: string[];
};
const assuranceLabels: Record<string, string> = {
  LOCAL_UNANCHORED: "로컬 기록 · 체인 확정 없음", SUBMITTED: "체인 전송 · 확정 대기",
  CONFIRMED: "설정된 확인 수 충족", ORPHANED: "체인 재조직 · 이전 확정 무효",
};
const short = (value?: string | null) => value ? `${value.slice(0, 12)}…${value.slice(-8)}` : "없음";
const date = (value?: string) => value ? new Date(value).toLocaleString("ko-KR") : "관측 없음";

export function ReceiptStatus({ record }: { record: ReceiptRecord }) {
  return <><span className={`ops-badge ${record.assurance === "CONFIRMED" ? "verified" : record.assurance === "ORPHANED" ? "revoked" : ""}`}>{record.assurance}</span>
    <small>{assuranceLabels[record.assurance] ?? "알 수 없는 상태 · 확정으로 판단하지 마세요."}</small>
    <small>확인 수 {record.confirmations} / {record.requiredConfirmations} · API 조회 기준</small>
    <small>전송 큐: {record.queueStatus ?? "작업 없음"} · 확정 상태와 별도</small>
    {record.errorCode && <small className="ops-flow-error">{record.errorCode}</small>}</>;
}

export function ReceiptEvidenceView({ batch, evidence }: { batch: ReceiptRecord; evidence: ReceiptEvidenceSummary | null }) {
  if (!evidence) return <p>증거 루트 검증: 아직 조회하지 않음. 체인 확정과 증거 검증은 별도입니다.</p>;
  if (evidence.verification !== "API_VERIFIED" || evidence.root !== batch.root) return <p className="ops-message error" role="alert">증거 루트 불일치 · 검증 완료로 표시하지 않습니다.</p>;
  return <p className="ops-message">API가 증거 루트를 검증함 · 증거 파일 {evidence.leafCount}개 · {date(evidence.checkedAt)}<br />브라우저 독립 검증이 아닙니다. 원문 영수증은 브라우저에 전달하지 않습니다.</p>;
}

// Even if an older response remains in memory, a failed refresh must never render its CONFIRMED label.
export function ReceiptRecordsView({ ledgers, batches, selected, error, busy = false, onSelect, onOpen }: {
  ledgers: ReceiptRecord[]; batches: ReceiptRecord[]; selected: string; error: string; busy?: boolean;
  onSelect?: (key: string) => void; onOpen?: (batch: ReceiptRecord) => void;
}) {
  if (error) return <p className="ops-message error" role="alert">{error}<br />현재 체인 상태를 확인할 수 없습니다. 이전 확정 표시는 숨겼습니다. 다시 조회하세요.</p>;
  return <><div className="ops-table-wrap"><table><caption>등록된 영수증 원장 · 현재 조직</caption><thead><tr><th>원장 / 공개 writer</th><th>체인 증빙</th><th>등록 트랜잭션</th><th>배치</th></tr></thead><tbody>{ledgers.map((ledger) => <tr key={ledger.ledgerKey} aria-selected={ledger.ledgerKey === selected}>
    <td><code title={ledger.ledgerKey}>{short(ledger.ledgerKey)}</code><small title={ledger.writer}>{short(ledger.writer)}</small><small>chain {ledger.chainId} · {short(ledger.registryAddress)}</small></td>
    <td><ReceiptStatus record={ledger} /></td><td><code title={ledger.txHash ?? ""}>{short(ledger.txHash)}</code><small>{date(ledger.observedAt)}{ledger.assurance === "ORPHANED" ? " · 이전 관측 기록" : ""}</small></td>
    <td><button disabled={busy} onClick={() => onSelect?.(ledger.ledgerKey)}>배치 조회</button></td></tr>)}</tbody></table></div>
    {!ledgers.length && <p className="ops-empty">불러온 원장이 없습니다. 빈 목록만으로 체인 기능의 설정 또는 검증 완료를 뜻하지 않습니다.</p>}
    {selected && <><h3>선택한 원장의 증거 배치</h3><p className="ops-data-note">최근 최대 250개 · 영수증 해시의 체크포인트이며 실제 도구 실행 사실을 증명하지 않습니다.</p><div className="ops-table-wrap"><table><thead><tr><th>배치 / 순번</th><th>데이터 출처</th><th>체인 증빙</th><th>트랜잭션</th><th>상세</th></tr></thead><tbody>{batches.map((batch) => <tr key={batch.batchId}>
      <td><code title={batch.batchId}>{short(batch.batchId)}</code><small>#{batch.fromSequence}–{batch.toSequence} · 영수증 {batch.count}개</small></td>
      <td>{batch.sources?.join(" + ") || "출처 미제공"}<small>{batch.sources?.some((source) => source !== "LIVE") ? "MOCK/REPLAY 포함 · 실운영 실행 증거 아님" : "LIVE 표기만으로 실행 사실 증명 아님"}</small></td>
      <td><ReceiptStatus record={batch} /></td><td><code title={batch.txHash ?? ""}>{short(batch.txHash)}</code></td><td><button disabled={busy} onClick={() => onOpen?.(batch)}>상세 조회</button></td></tr>)}</tbody></table></div>{!batches.length && <p className="ops-empty">등록된 배치가 없습니다. writer CLI에서 로컬 원장 검증·배치 제출·서명을 진행하세요.</p>}</>}
  </>;
}

export function ReceiptConsole({ manage, evidenceAccess }: { manage: boolean; evidenceAccess: boolean }) {
  const [ledgers, setLedgers] = useState<ReceiptRecord[]>([]), [batches, setBatches] = useState<ReceiptRecord[]>([]);
  const [selected, setSelected] = useState(""), [detail, setDetail] = useState<ReceiptRecord | null>(null);
  const [evidence, setEvidence] = useState<ReceiptEvidenceSummary | null>(null);
  const [busy, setBusy] = useState(false), [loaded, setLoaded] = useState(false), [error, setError] = useState(""), [message, setMessage] = useState("");
  const registration = useRef<{ writer: string; key: string } | null>(null);
  async function perform(work: () => Promise<void>) {
    setBusy(true); setError(""); setMessage(""); setEvidence(null); setDetail(null);
    try { await work(); } catch (error) {
      setLedgers([]); setBatches([]); setDetail(null); setLoaded(false);
      setError(error instanceof Error ? error.message : "영수증 API 조회 실패");
    } finally { setBusy(false); }
  }
  async function refresh(key = selected) {
    // All-or-nothing refresh: no combination of a fresh ledger and stale batch finality.
    setLedgers([]); setBatches([]);
    const [next, batchList] = await Promise.all([controlApi<{ items: ReceiptRecord[] }>("receipt-ledgers"), key ? controlApi<{ items: ReceiptRecord[] }>(`receipt-ledgers/${encodeURIComponent(key)}/batches`) : Promise.resolve({ items: [] })]);
    setLedgers(next.items); setBatches(batchList.items); setSelected(key); setLoaded(true);
  }
  function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = event.currentTarget;
    const writer = String(new FormData(form).get("writer") ?? "").trim().toLowerCase();
    if (!validReceiptWriter(writer)) { setError("0이 아닌 공개 writer 주소(0x + 40자리 hex)를 입력하세요. 개인키는 입력하지 마세요."); return; }
    if (registration.current?.writer !== writer) registration.current = { writer, key: crypto.randomUUID() };
    const key = registration.current.key;
    void perform(async () => {
      const { ledger } = await controlApi<{ ledger: ReceiptRecord }>("receipt-ledgers", { writer }, "POST", key);
      // Retain the logical idempotency key through an uncertain response or refresh failure.
      await refresh(ledger.ledgerKey);
      registration.current = null; form.reset();
      setMessage("원장 등록 요청을 접수했습니다. 전송 큐와 체인 확인 수를 별도로 확인하세요.");
    });
  }
  return <section className="ops-panel ops-receipts" aria-label="고위험 작업 영수증">
    <div className="ops-section-heading"><h2>고위험 작업 영수증</h2><span className="ops-badge">V2 운영 API · 출처별 표시</span></div>
    <p>로컬 기록 → writer 서명 제출 → 체인 전송 → 설정된 확인 수 충족. 큐의 COMPLETED만으로 확정하지 않습니다.</p>
    <p>개인키·API 키·도구의 원문 인자는 여기서 수집하지 않습니다. 배치 제출과 서명은 실제 writer CLI에서 수행해야 합니다. 공개 주소 형식 확인은 키 소유 증명이 아닙니다.</p>
    <button disabled={busy} onClick={() => void perform(() => refresh())}>{busy ? "조회 중…" : "원장·체인 상태 새로고침"}</button>
    {message && <p className="ops-message" role="status">{message}</p>}
    {loaded || error ? <ReceiptRecordsView ledgers={ledgers} batches={batches} selected={selected} error={error} busy={busy} onSelect={(key) => void perform(() => refresh(key))} onOpen={(batch) => void perform(async () => { const { batch: current } = await controlApi<{ batch: ReceiptRecord }>(`receipt-batches/${encodeURIComponent(batch.batchId!)}`); setBatches((items) => items.map((item) => item.batchId === current.batchId ? current : item)); setDetail(current); })} /> : <p className="ops-empty">아직 조회하지 않았습니다. 영수증 체인 기능은 별도 서버 설정이 필요하며, 미설정 시 성공으로 대체하지 않습니다.</p>}
    {!error && detail && <article className="ops-receipt-detail"><h3>배치 상세</h3><dl className="ops-facts">{[["Batch ID", detail.batchId], ["Merkle root", detail.root], ["Ledger key", detail.ledgerKey], ["Chain / registry", `${detail.chainId} / ${detail.registryAddress}`], ["Transaction", detail.txHash], [detail.assurance === "ORPHANED" ? "이전 관측 블록 (현재 확정 아님)" : "API 관측 블록", detail.observedBlock], ["관측 블록 해시", detail.observedBlockHash], ["API 체인 관측 시각", date(detail.observedAt)]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? "기록 없음"}</dd></div>)}</dl>
      <div className="ops-receipt-status"><ReceiptStatus record={detail} /></div>
      <ReceiptEvidenceView batch={detail} evidence={evidence} />
      {evidenceAccess ? <button disabled={busy} onClick={() => { const batch = detail; void perform(async () => {
        const [current, summary] = await Promise.all([controlApi<{ batch: ReceiptRecord }>(`receipt-batches/${encodeURIComponent(batch.batchId!)}`), controlApi<ReceiptEvidenceSummary>(`receipt-batches/${encodeURIComponent(batch.batchId!)}/evidence`)]);
        setBatches((items) => items.map((item) => item.batchId === current.batch.batchId ? current.batch : item)); setDetail(current.batch); setEvidence(summary);
      }); }}>API 증거 검증 결과 조회</button> : <p className="ops-data-note">reader는 메타데이터만 조회할 수 있습니다. 증거 검증 결과 조회는 operator/admin 권한이 필요합니다.</p>}
    </article>}
    {manage && <details className="ops-chain-admin"><summary>관리자 · 영수증 원장 등록</summary><p>서버에 설정된 체인에 writer 공개 주소를 등록합니다. 가스 비용이 발생할 수 있습니다. 서명 권한을 부여할 주소를 확인하세요.</p><form method="post" onSubmit={register}><label>writer 공개 주소<input name="writer" required minLength={42} maxLength={42} pattern="0x[0-9a-fA-F]{40}" placeholder="0x + 40자리 공개 주소" autoComplete="off" spellCheck={false} disabled={busy} /></label><label className="ops-check"><input type="checkbox" required disabled={busy} />이 공개 주소를 writer로 지정하여 원장 등록을 요청합니다.</label><button disabled={busy}>원장 등록 요청</button></form><p className="ops-data-note">응답이 불확실하면 같은 주소로 재시도하세요. 이 화면에서는 같은 요청 식별키를 유지합니다. 페이지를 새로 열기 전 기존 원장 목록을 확인하세요.</p></details>}
  </section>;
}
