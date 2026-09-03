"use client";

import { useState } from "react";
import { mockSnapshot } from "../lib/demo-data";
import type { Snapshot, Source } from "../lib/types";

const short = (value: string) => `${value.slice(0, 12)}…${value.slice(-6)}`;

export function Dashboard() {
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("Mock mode uses deterministic, local demo data.");

  async function selectSource(source: Source) {
    if (source === "MOCK") {
      setSnapshot(mockSnapshot);
      setNotice("Mock mode uses deterministic, local demo data.");
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(source === "LIVE" ? "/api/live" : "/api/replay", { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setSnapshot(await response.json());
      setNotice(source === "LIVE" ? "Live mode is connected to the Backend API." : "Replay mode is showing the saved offline evidence bundle.");
    } catch (error) {
      if (source === "LIVE") {
        const replay = await fetch("/api/replay", { cache: "no-store" });
        if (replay.ok) setSnapshot(await replay.json());
        setNotice(`Live API unavailable (${error instanceof Error ? error.message : "unknown error"}); switched explicitly to REPLAY.`);
      } else {
        setNotice(`Replay failed: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    } finally {
      setLoading(false);
    }
  }

  const malicious = snapshot.releases.find((release) => release.releaseId.endsWith("1.0.1"));
  const failVotes = snapshot.validators.filter((validator) => validator.decision === "FAIL").length;

  return (
    <main>
      <header className="hero">
        <div>
          <div className="eyebrow"><span className="shield">M</span> MCPShield / Control Room</div>
          <h1>Trust the release.<br /><em>Not the signature.</em></h1>
          <p>Deterministic evidence, validator quorum, and pre-spawn enforcement for MCP runtimes.</p>
        </div>
        <div className="source-panel" aria-label="Data source selector">
          {(["MOCK", "LIVE", "REPLAY"] as Source[]).map((source) => (
            <button key={source} className={snapshot.source === source ? "active" : ""} onClick={() => selectSource(source)} disabled={loading}>{source}</button>
          ))}
          <span className={`source-badge ${snapshot.source.toLowerCase()}`}>{loading ? "LOADING" : snapshot.source}</span>
        </div>
      </header>

      <div className="notice" role="status"><span />{notice}</div>

      <section className="metrics">
        <article><span>Release status</span><strong className="danger">{malicious?.chainStatus ?? "UNAVAILABLE"}</strong><small>mail-mcp@1.0.1</small></article>
        <article><span>Validator quorum</span><strong>{failVotes} / 3</strong><small>{failVotes >= 2 ? "Threshold reached" : "Awaiting votes"}</small></article>
        <article><span>Gateway enforcement</span><strong className="danger">{snapshot.admissions.filter((item) => item.decision === "BLOCK").length} BLOCK</strong><small>before process spawn</small></article>
      </section>

      <section className="card wide">
        <div className="section-title"><div><span>01</span><h2>Release compare</h2></div><p>Signed artifacts can still change behavior.</p></div>
        <div className="release-grid">
          {snapshot.releases.map((release, index) => (
            <article className="release" key={release.releaseId}>
              <div className="release-head"><span className="version">{index === 0 ? "BASELINE" : "CANDIDATE"}</span><span className={`status ${release.chainStatus.toLowerCase()}`}>{release.chainStatus}</span></div>
              <h3>{release.releaseId}</h3>
              <dl>
                <div><dt>Signature</dt><dd className="good">{release.signature}</dd></div>
                <div><dt>Artifact</dt><dd title={release.artifactDigest}>{short(release.artifactDigest)}</dd></div>
                <div><dt>Tool surface</dt><dd title={release.toolSurfaceHash}>{short(release.toolSurfaceHash)}</dd></div>
                <div><dt>Scan</dt><dd>{release.scanStatus}</dd></div>
              </dl>
            </article>
          ))}
          <div className="change-arrow" aria-hidden="true">→<span>behavior drift</span></div>
        </div>
      </section>

      <div className="two-column">
        <section className="card">
          <div className="section-title"><div><span>02</span><h2>Scan pipeline</h2></div></div>
          <ol className="pipeline">
            {snapshot.pipeline.map((item, index) => (
              <li key={item.stage}><span className="step">0{index + 1}</span><div><b>{item.stage}</b><p>{item.detail}</p></div><strong className={item.status === "FAILED" || item.status === "FLAGGED" ? "danger" : "good"}>{item.status}</strong></li>
            ))}
          </ol>
        </section>

        <section className="card">
          <div className="section-title"><div><span>03</span><h2>Sandbox timeline</h2></div></div>
          <ol className="timeline">
            {snapshot.sandboxEvents.map((event) => (
              <li key={`${event.time}-${event.type}`} className={event.level.toLowerCase()}><time>{event.time}</time><div><b>{event.type}</b><p>{event.detail}</p></div></li>
            ))}
          </ol>
        </section>
      </div>

      <div className="two-column lower">
        <section className="card">
          <div className="section-title"><div><span>04</span><h2>Validator / chain</h2></div><strong className="quorum">2-of-3</strong></div>
          <div className="validators">
            {snapshot.validators.map((validator) => <div key={validator.id}><span className="avatar">{validator.id.slice(-1)}</span><b>{validator.id}</b><strong className={validator.decision === "FAIL" ? "danger" : "muted"}>{validator.decision}</strong></div>)}
          </div>
          <div className="chain-state"><span>On-chain status</span><strong>{malicious?.chainStatus ?? "UNAVAILABLE"}</strong>{malicious?.txHash && <a href={`https://sepolia.basescan.org/tx/${malicious.txHash}`} target="_blank" rel="noreferrer">View transaction ↗</a>}</div>
        </section>

        <section className="card">
          <div className="section-title"><div><span>05</span><h2>Agent admission</h2></div></div>
          <div className="admissions">
            {snapshot.admissions.map((item, index) => (
              <article key={`${item.gateway}-${item.releaseId}-${index}`}><div><small>{item.gateway}</small><b>{item.releaseId}</b></div><strong className={item.decision === "BLOCK" ? "block" : "allow"}>{item.decision}</strong><p>{item.reasonCode.replaceAll("_", " ")}</p></article>
            ))}
          </div>
        </section>
      </div>

      <footer><span>MCPShield</span><p>Evidence-first MCP supply chain security · {new Date(snapshot.generatedAt).toLocaleString()}</p><span className={`source-badge ${snapshot.source.toLowerCase()}`}>{snapshot.source}</span></footer>
    </main>
  );
}
