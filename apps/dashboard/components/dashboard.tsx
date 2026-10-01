"use client";

import { useState } from "react";
import { mockSnapshot, unavailableSnapshot } from "../lib/demo-data";
import type { Snapshot, Source } from "../lib/types";

const short = (value: string) => `${value.slice(0, 12)}…${value.slice(-6)}`;
const pipelineTone = (status: string) => status === "FAILED" || status === "FLAGGED" ? "danger" : status === "PASSED" ? "good" : "muted";

export function Dashboard() {
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("Mock mode uses deterministic, local demo data.");
  const [error, setError] = useState<string | null>(null);

  async function selectSource(source: Source) {
    setError(null);
    if (source === "MOCK") {
      setSnapshot(mockSnapshot);
      setNotice("Mock mode uses deterministic, local demo data.");
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(source === "LIVE" ? "/api/live" : "/api/replay", { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const next = await response.json() as Snapshot;
      setSnapshot(next);
      setNotice(source === "LIVE" ? "Live mode is connected to the Backend API." : "Replay mode is showing the saved offline evidence bundle.");
    } catch (error) {
      if (source === "LIVE") {
        const message = `Live API unavailable (${error instanceof Error ? error.message : "unknown error"})`;
        try {
          const replay = await fetch("/api/replay", { cache: "no-store" });
          if (!replay.ok) throw new Error(`HTTP ${replay.status}`);
          setSnapshot(await replay.json());
          setError(message);
          setNotice(`${message}; switched explicitly to REPLAY.`);
        } catch (replayError) {
          const combined = `${message}; Replay unavailable (${replayError instanceof Error ? replayError.message : "unknown error"}). Stale evidence was cleared.`;
          setSnapshot(unavailableSnapshot("LIVE"));
          setError(combined);
          setNotice(combined);
        }
      } else {
        const message = `Replay failed: ${error instanceof Error ? error.message : "unknown error"}`;
        setSnapshot(unavailableSnapshot("REPLAY"));
        setError(message);
        setNotice(message);
      }
    } finally {
      setLoading(false);
    }
  }

  const malicious = snapshot.releases.find((release) => release.releaseId.endsWith("1.0.1"));
  const baseline = snapshot.releases.find((release) => release.releaseId.endsWith("1.0.0"));
  const failVotes = snapshot.validators.filter((validator) => validator.decision === "FAIL").length;
  const explorer = snapshot.explorerBaseUrl?.replace(/\/$/, "");
  const hasLiveGatewayProof = snapshot.admissions.length > 0 && snapshot.admissions.every((item) => item.source === "LIVE" && item.spawnAttempted === false);
  const admissionMetric = hasLiveGatewayProof ? ["Gateway enforcement", "before process spawn"] : snapshot.source === "LIVE" ? ["Backend admission preview", "no spawn proof"] : ["Admission preview", "no live spawn proof"];

  return (
    <main>
      <header className="hero">
        <div>
          <div className="eyebrow"><span className="shield">M</span> MCPShield / Control Room</div>
          <h1>Trust the release.<br /><em>Not the signature.</em></h1>
          <p>Deterministic evidence, validator quorum, and pre-spawn enforcement for MCP runtimes.</p>
        </div>
        <div className="source-panel" aria-label="Data source selector" aria-busy={loading}>
          <a className="judge-entry" href="/try">TRY</a>
          <a className="judge-entry" href="/console">CONSOLE</a>
          {(["MOCK", "LIVE", "REPLAY"] as Source[]).map((source) => (
            <button key={source} className={snapshot.source === source ? "active" : ""} onClick={() => selectSource(source)} disabled={loading} aria-pressed={snapshot.source === source}>{source}</button>
          ))}
          <span className={`source-badge ${snapshot.source.toLowerCase()}`}>{loading ? "LOADING" : snapshot.source}</span>
        </div>
      </header>

      <div className={`notice ${error ? "notice-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite"><span />{notice}</div>

      <section className="source-explainer" aria-label="Evidence source details">
        <strong>{snapshot.availability ?? snapshot.source}</strong>
        <p>{snapshot.availability === "UNAVAILABLE" ? `No current ${snapshot.source} evidence is loaded; no release, scan, validator, or Gateway claim is shown.` : snapshot.source === "LIVE" ? "Fetched now from the Backend API and, when configured, Gateway probe evidence files." : snapshot.source === "REPLAY" ? "Saved offline evidence; no live security claim is implied." : "Deterministic product preview; values are synthetic and never presented as live."}</p>
        <span>{snapshot.availability === "UNAVAILABLE" ? "NO EVIDENCE" : snapshot.ledgerMode === "LOCAL_DEMO" ? "LOCAL DEMO LEDGER · NOT ON-CHAIN" : snapshot.ledgerMode ?? (snapshot.source === "LIVE" ? "UNKNOWN LEDGER" : "OFFLINE")}</span>
      </section>

      <section className="metrics">
        <article><span>Release status</span><strong className="danger">{malicious?.chainStatus ?? "UNAVAILABLE"}</strong><small>mail-mcp@1.0.1</small></article>
        <article><span>Validator quorum</span><strong>{failVotes} / 3</strong><small>{failVotes >= 2 ? "Threshold reached" : "Awaiting votes"}</small><progress max="3" value={failVotes} aria-label={`${failVotes} of 3 validator failure votes`} /></article>
        <article><span>{admissionMetric[0]}</span><strong className="danger">{snapshot.admissions.filter((item) => item.decision === "BLOCK").length} BLOCK</strong><small>{admissionMetric[1]}</small></article>
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
          {snapshot.releases.length === 0 && <p className="empty-state">No current release evidence is available.</p>}
          {snapshot.releases.length === 2 && <div className="change-arrow" aria-hidden="true">→<span>behavior drift</span></div>}
        </div>
        {snapshot.releases.length === 2 && <div className="diff-summary" aria-label="Release identity changes">
          <span className={baseline?.artifactDigest !== malicious?.artifactDigest ? "changed" : "same"}>Artifact digest {baseline?.artifactDigest !== malicious?.artifactDigest ? "changed" : "unchanged"}</span>
          <span className={baseline?.toolSurfaceHash !== malicious?.toolSurfaceHash ? "changed" : "same"}>Tool surface {baseline?.toolSurfaceHash !== malicious?.toolSurfaceHash ? "changed" : "unchanged"}</span>
          <span>Publisher signature {malicious?.signature ?? "UNKNOWN"}</span>
        </div>}
      </section>

      <div className="two-column">
        <section className="card">
          <div className="section-title"><div><span>02</span><h2>Scan pipeline</h2></div></div>
          <ol className="pipeline">
            {snapshot.pipeline.map((item, index) => (
              <li key={item.stage}><span className="step">0{index + 1}</span><div><b>{item.stage}</b><p>{item.detail}</p></div><strong className={pipelineTone(item.status)}>{item.status}</strong></li>
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
            {snapshot.validators.length === 0 && <p className="empty-state">No validator votes are available from this source.</p>}
          </div>
          <div className="chain-state"><span>{snapshot.ledgerMode === "LOCAL_DEMO" ? "Local demo ledger status" : "On-chain status"}</span><strong>{malicious?.chainStatus ?? "UNAVAILABLE"}</strong>{malicious?.txHash && explorer ? <a href={`${explorer}/tx/${encodeURIComponent(malicious.txHash)}`} target="_blank" rel="noreferrer" aria-label="View status transaction in a new tab">View transaction ↗</a> : malicious?.txHash ? <code title={malicious.txHash}>{short(malicious.txHash)}</code> : null}</div>
        </section>

        <section className="card">
          <div className="section-title"><div><span>05</span><h2>Agent admission</h2></div></div>
          <div className="admissions">
            {snapshot.admissions.map((item, index) => (
              <article key={`${item.gateway}-${item.releaseId}-${index}`}><div><small>{item.gateway}</small><b>{item.releaseId}</b></div><strong className={item.decision === "BLOCK" ? "block" : "allow"}>{item.decision}</strong><p>{item.reasonCode.replaceAll("_", " ")}{item.spawnAttempted === false ? " · PRE-SPAWN PROBE" : ""}</p></article>
            ))}
            {snapshot.admissions.length === 0 && <p className="empty-state">No current Gateway admission decisions are available.</p>}
          </div>
        </section>
      </div>

      <footer><span>MCPShield</span><p>Evidence-first MCP supply chain security · <time dateTime={snapshot.generatedAt}>{snapshot.generatedAt}</time></p><button className="refresh" onClick={() => selectSource(snapshot.source)} disabled={loading} aria-label={`Refresh ${snapshot.source} data`}>Refresh</button><span className={`source-badge ${snapshot.source.toLowerCase()}`}>{snapshot.source}</span></footer>
    </main>
  );
}
