import type { Metadata } from "next";
import { readLedger, type Ledger, type LedgerRelease } from "../../lib/ledger-v3";
import "./ledger.css";

export const metadata: Metadata = {
  title: "MCPShield Ledger",
  description: "ReleaseRegistryV3 on Base Sepolia, read straight from chain",
};
export const dynamic = "force-dynamic";

// Repeated page loads within 20 s reuse one chain read (each read makes ~20 public RPC calls).
let cached: { at: number; ledger: Promise<Ledger> } | null = null;
function ledger() {
  if (!cached || Date.now() - cached.at > 20_000) {
    cached = { at: Date.now(), ledger: readLedger() };
    cached.ledger.catch(() => { cached = null; });
  }
  return cached.ledger;
}

const short = (value: string, head = 10) => `${value.slice(0, head)}…${value.slice(-4)}`;
const statusText: Record<string, string> = { VERIFIED: "승인됨", REVOKED: "폐기됨", QUARANTINED: "격리 중", UNVERIFIED: "미검증", EXPIRED: "만료" };
const verdictText: Record<string, string> = { PASS: "통과", FAIL: "실패", ABSTAIN: "보류" };
const outcomeText: Record<string, string> = { APPROVED: "승인 (2/3 PASS)", REJECTED: "폐기 (2/3 FAIL)", SPLIT: "표 갈림 → 사람 검토", OPEN: "진행 중" };

function Tx({ explorer, hash }: { explorer?: string; hash: string }) {
  return explorer ? <a className="mono" href={`${explorer}/tx/${hash}`} target="_blank" rel="noreferrer">{short(hash)}</a> : <span className="mono">{short(hash)}</span>;
}

function Release({ release, explorer }: { release: LedgerRelease; explorer?: string }) {
  return (
    <section className="ledger-release" aria-labelledby={`r-${release.releaseId}`}>
      <header>
        <div>
          <h2 id={`r-${release.releaseId}`}>{release.name ?? "이름 없는 릴리스"} <span className="mono muted">{short(release.releaseId, 14)}</span></h2>
          <p className="muted">배포본 <span className="mono">{short(release.artifactDigest)}</span> · 도구 목록 <span className="mono">{short(release.toolSurfaceDigest)}</span></p>
        </div>
        <span className={`ledger-status s-${release.status}`}>{statusText[release.status] ?? release.status}</span>
      </header>
      {release.needsReview && <p className="ledger-review" role="status">표가 갈려 실행이 멈춰 있습니다. 검증자 회사의 사람 검토 후 새 라운드가 필요합니다.</p>}

      <h3>Gateway 판정 (각 회사가 자기 RPC로 체인만 읽음)</h3>
      <div className="ledger-gates">
        {release.admission.map((a) => (
          <div key={a.company} className={`ledger-gate g-${a.decision}`}>
            <strong>{a.company}</strong>
            <span>{a.decision === "ALLOW" ? "실행 허용" : "실행 차단"}</span>
            <small className="mono">{a.reasonCode}{a.observedBlock ? ` · 블록 ${a.observedBlock}` : ""}</small>
            {a.error && <small>판정을 확정하지 못해 차단했습니다(fail-closed): <span className="mono">{a.error}</span></small>}
          </div>
        ))}
      </div>

      {release.rounds.map((round) => (
        <div key={round.roundId} className="ledger-round">
          <h3>검사 라운드 <span className="mono">{short(round.roundId)}</span> · {outcomeText[round.outcome] ?? round.outcome}{round.live ? " · 현재 판정 근거" : ""}</h3>
          <table>
            <thead><tr><th>검증자</th><th>판정</th><th>자기 증거 해시</th><th>기록 시점</th><th>거래</th></tr></thead>
            <tbody>
              {round.votes.map((vote) => (
                <tr key={vote.txHash} className={vote.afterDecision ? "after" : undefined}>
                  <td>{vote.label}</td>
                  <td className={`v-${vote.verdict}`}>{verdictText[vote.verdict] ?? vote.verdict}</td>
                  <td className="mono">{short(vote.evidenceHash)}</td>
                  <td>{vote.afterDecision ? "결정 후 (반대·추가 표도 남음)" : "결정 전"}</td>
                  <td><Tx explorer={explorer} hash={vote.txHash} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      <h3>체인 기록 순서</h3>
      <ol className="ledger-events">
        {release.events.map((event) => (
          <li key={`${event.txHash}-${event.kind}-${event.actor ?? ""}`} className={`e-${event.kind}`}>
            <span>{event.detail}</span> <span className="muted">블록 {event.block}</span> <Tx explorer={explorer} hash={event.txHash} />
          </li>
        ))}
      </ol>
    </section>
  );
}

export default async function LedgerPage() {
  let data: Ledger | null = null, failure: string | null = null;
  try { data = await ledger(); } catch (error: any) { failure = /^[A-Z_]+$/.test(error?.message ?? "") ? error.message : "CHAIN_READ_FAILED"; }
  return (
    <main className="ledger">
      <header className="ledger-hero">
        <p className="eyebrow">MCPShield · ReleaseRegistryV3 · Base Sepolia</p>
        <h1>운영사를 거치지 않고, 체인만 읽은 화면입니다.</h1>
        <p className="muted">검증자 3곳은 각자 검사하고 자기 증거 해시에 서명합니다. 셋 중 둘이 같은 판정을 내면 체인 상태가 바뀌고, 반대표도 지워지지 않습니다.
          거래 목록은 위치만 알려 줄 뿐이고, 모든 내용은 체인에서 다시 읽은 영수증과 컨트랙트 상태입니다.</p>
        {data && <p className="muted small">레지스트리 {data.config.explorer
          ? <a className="mono" href={`${data.config.explorer}/address/${data.config.registry}`} target="_blank" rel="noreferrer">{short(data.config.registry, 12)}</a>
          : <span className="mono">{data.config.registry}</span>} · 정책 <span className="mono">{data.policyHash ? short(data.policyHash) : "없음"}</span> · 최신 블록 {data.head} · {new Date(data.readAt).toLocaleString("ko-KR")}</p>}
      </header>
      {failure && <p role="alert" className="ledger-review">체인을 읽지 못했습니다(<span className="mono">{failure}</span>). 이 화면은 다른 저장소의 값으로 대신 채우지 않습니다.</p>}
      {data?.releases.map((release) => <Release key={release.releaseId} release={release} explorer={data!.config.explorer} />)}
    </main>
  );
}
