// V3 operator API access for the Figma scan screens: calls through the /api/control proxy (httpOnly session cookie set by
// the console login), the start-a-scan flow and polling hooks. Polling only; the per-tenant event stream slots stay free.
import { useEffect, useState } from "react";
import { controlApi } from "../../lib/control-client";
import { admissionRequest, type Admission, type ChainAction, type Release, type Scan, type V3Votes } from "../release-workflow";
import { flowView, progressPhase, shownRound, type FixtureVersion, type HistoryItem, type Phase } from "./v3-model";

export type Session = { tenantId: string; role: string; capabilities: { read: boolean; scan: boolean; evidence: boolean; manage: boolean }; registryVersion?: number | null };
export type Policy = { policyHash: string; alias: string; version: string; document: unknown; createdAt: string; deprecatedAt: string | null };
export type SessionState = { status: "loading" } | { status: "signed-in"; session: Session } | { status: "signed-out" } | { status: "error"; message: string };
type Api = typeof controlApi;

const statusOf = (error: unknown) => (error as { status?: number } | null)?.status;
const messageOf = (error: unknown) => error instanceof Error ? error.message : "조회 실패";
export const unreachable = (status?: number) => `운영 API에 연결할 수 없습니다 (${status ?? "네트워크 오류"}). 스택이 실행 중인지 확인하세요.`;
export const defaultPolicyOf = (policies: Policy[] | null | undefined) => policies?.find((item) => item.alias === "mvp-default-v1" && !item.deprecatedAt);
/** The chain vote view of one release under the policy the site scans with (the API would otherwise pick the newest scan's policy). */
export const votesPath = (releaseId: string, policyHash?: string | null) =>
  `releases/${encodeURIComponent(releaseId)}/votes${policyHash && /^0x[0-9a-f]{64}$/.test(policyHash) ? `?policyHash=${policyHash}` : ""}`;
const DECIDED = new Set(["APPROVED", "REJECTED", "SPLIT"]);

/** The operator session. While signed out (or unreachable) it asks again every few seconds, so a login made on /console in another
 *  tab shows up here without a reload, the same way the sidebar does. */
export function useSession(): SessionState {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const read = () => controlApi<Session>("session", undefined, "GET", undefined, controller.signal)
      .then((session) => setState({ status: "signed-in", session }))
      .catch((error) => {
        if (controller.signal.aborted) return;
        const signedOut = statusOf(error) === 401;
        setState(signedOut ? { status: "signed-out" } : { status: "error", message: unreachable(statusOf(error)) });
        timer = setTimeout(read, signedOut ? 2500 : 5000);
      });
    void read();
    return () => { controller.abort(); if (timer) clearTimeout(timer); };
  }, []);
  return state;
}

export type Board = { releases: Release[]; scans: Scan[]; policies: Policy[]; actions: ChainAction[]; votes: Record<string, V3Votes | undefined>;
  /** releaseId → why its chain vote view could not be read. Such a release has no state on screen, never the database copy. */
  voteErrors: Record<string, string>; defaultPolicy?: Policy };
/** Releases, scans, policies, chain actions and the chain vote view of every fixture release (and every release that has a scan). */
export function useBoard(enabled: boolean) {
  const [board, setBoard] = useState<Board | null>(null);
  const [error, setError] = useState("");
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController(), signal = controller.signal;
    const get = <T,>(path: string) => controlApi<T>(path, undefined, "GET", undefined, signal);
    (async () => {
      try {
        const [releases, scans, policies, actions] = await Promise.all([get<{ items: Release[] }>("releases"), get<{ items: Scan[] }>("scans"),
          get<{ items: Policy[] }>("policies"), get<{ items: ChainAction[] }>("chain/actions")]);
        const defaultPolicy = defaultPolicyOf(policies.items);
        const wanted = releases.items.filter((item) => item.legacyReleaseId === "mail-mcp@1.0.0" || item.legacyReleaseId === "mail-mcp@1.0.1"
          || scans.items.some((scan) => scan.releaseId === item.releaseId));
        const votes = await Promise.allSettled(wanted.map((item) => get<V3Votes>(votesPath(item.releaseId, defaultPolicy?.policyHash))));
        if (signal.aborted) return;
        const failure = (result: PromiseSettledResult<V3Votes>) => result.status === "rejected"
          ? (statusOf(result.reason) && statusOf(result.reason)! >= 500 ? unreachable(statusOf(result.reason)) : messageOf(result.reason)) : null;
        setBoard({ releases: releases.items, scans: scans.items, policies: policies.items, actions: actions.items, defaultPolicy,
          votes: Object.fromEntries(wanted.map((item, index) => [item.releaseId, votes[index].status === "fulfilled" ? (votes[index] as PromiseFulfilledResult<V3Votes>).value : undefined])),
          voteErrors: Object.fromEntries(wanted.flatMap((item, index) => { const message = failure(votes[index]); return message ? [[item.releaseId, message]] : []; })) });
        setError("");
      } catch (failure) {
        if (!signal.aborted) setError(statusOf(failure) && statusOf(failure)! >= 500 ? unreachable(statusOf(failure)) : messageOf(failure));
      }
    })();
    return () => controller.abort();
  }, [enabled, nonce]);
  return { board, error, refresh: () => setNonce((value) => value + 1) };
}

/** Strict admission lookup for the exact release (the same request the console sends). It reads the API; it never runs a tool. */
export const checkAdmission = (release: Release, policyHash: string, signal?: AbortSignal) =>
  controlApi<Admission>("admission/check", admissionRequest(release, policyHash), "POST", undefined, signal);

/** The newest COMPLETED operator scan, for /scan-results opened without a scan or release. undefined = still looking, null = none. */
export function useLatestScan(enabled: boolean) {
  const [state, setState] = useState<{ scanId: string | null | undefined; signedOut: boolean; error: string }>({ scanId: undefined, signedOut: false, error: "" });
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    controlApi<{ items: Scan[] }>("scans", undefined, "GET", undefined, controller.signal)
      .then(({ items }) => setState({ scanId: [...items].filter((scan) => scan.status === "COMPLETED").sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0]?.scanId ?? null, signedOut: false, error: "" }))
      .catch((failure) => { if (!controller.signal.aborted) setState({ scanId: null, signedOut: statusOf(failure) === 401, error: statusOf(failure) === 401 ? "" : messageOf(failure) }); });
    return () => controller.abort();
  }, [enabled]);
  return state;
}

export type StartPhase = "resolving" | "registering" | "requesting";
export type StartResult = { kind: "scan"; scanId: string; reused: boolean } | { kind: "revoked"; releaseId: string };
export type StartDeps = { api: Api; capabilities: Session["capabilities"]; policies: Policy[]; attemptKey: string; onPhase: (phase: StartPhase) => void; sleep?: (ms: number) => Promise<void> };

/**
 * "보안 검사 시작": resolve the reviewed fixture, register the exact release on chain if it is not there yet (admin only), then ask
 * for an operator scan. The operator scan only announces a round; validators A, B and C decide it. A REVOKED release is final,
 * so no new scan is opened for it. One attemptKey per click: retrying the same click never opens a second scan.
 */
export async function startScan(version: FixtureVersion, deps: StartDeps): Promise<StartResult> {
  const policy = defaultPolicyOf(deps.policies);
  if (!policy) throw new Error("기본 정책(mvp-default-v1)을 찾지 못했습니다.");
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  deps.onPhase("resolving");
  const { release } = await deps.api<{ release: Release }>("releases/resolve", { sourceType: "fixture", locator: `mail-mcp-${version}` });
  const votes = await deps.api<V3Votes>(votesPath(release.releaseId, policy.policyHash));
  if ((votes.status ?? release.status) === "REVOKED") return { kind: "revoked", releaseId: release.releaseId };
  if (!votes.registered) {
    if (!deps.capabilities.manage) throw new Error("이 버전은 아직 체인에 없습니다. 온체인 등록은 관리자 토큰이 필요합니다.");
    deps.onPhase("registering");
    // The action id is the request hash, so asking again for the same release returns the same action.
    const { action } = await deps.api<{ action: ChainAction }>(`releases/${encodeURIComponent(release.releaseId)}/register`, {});
    let current = action;
    for (let attempt = 0; current.status !== "COMPLETED"; attempt++) {
      if (current.status === "FAILED" || current.status === "DEAD_LETTER") throw new Error(`온체인 등록 실패 · ${current.errorCode ?? current.status}`);
      if (attempt >= 60) throw new Error("온체인 등록 확인이 60초 안에 끝나지 않았습니다. 운영 콘솔의 전송 작업 기록을 확인하세요.");
      await sleep(1000);
      current = (await deps.api<{ action: ChainAction }>(`chain/actions/${encodeURIComponent(action.actionId)}`)).action;
    }
  }
  deps.onPhase("requesting");
  const response = await deps.api<{ scan: Scan; reusedResult?: boolean }>("scans", { releaseId: release.releaseId, policyHash: policy.policyHash }, "POST", deps.attemptKey);
  return { kind: "scan", scanId: response.scan.scanId, reused: Boolean(response.reusedResult) };
}

export type RunState = { loading: boolean; signedOut: boolean; notFound: boolean; error: string; release: Release | null; scan: Scan | null; votes: V3Votes | null;
  history: HistoryItem[]; actions: ChainAction[]; policies: Policy[]; admission: Admission | null; admissionPending: boolean; at: number };
const EMPTY: RunState = { loading: true, signedOut: false, notFound: false, error: "", release: null, scan: null, votes: null, history: [], actions: [], policies: [], admission: null, admissionPending: false, at: 0 };

/**
 * One scan (or one release's deciding round) read from the operator API on a timer. Admission is asked only after the round has
 * a result, and asked again (2 s apart, at most 3 more times) while it still disagrees with the chain view because of confirmations.
 * A failed read keeps the last good data and its time (`at`); the screen says so instead of showing it as current.
 */
export function useV3Run(target: { scanId?: string | null; releaseId?: string | null }, { poll }: { poll: boolean }) {
  const session = useSession();
  const signedIn = session.status === "signed-in";
  const [state, setState] = useState<RunState>(EMPTY);
  const [nonce, setNonce] = useState(0);
  const { scanId, releaseId } = target;
  useEffect(() => {
    if (!signedIn || (!scanId && !releaseId)) return;
    const controller = new AbortController(), signal = controller.signal;
    const get = <T,>(path: string) => controlApi<T>(path, undefined, "GET", undefined, signal);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const memo = { release: null as Release | null, scan: null as Scan | null, actions: [] as ChainAction[], registered: false, policies: null as Policy[] | null,
      admission: null as Admission | null, tries: 0, askedAt: 0 };
    setState(EMPTY);
    const tick = async () => {
      try {
        if (scanId) memo.scan = (await get<{ scan: Scan }>(`scans/${encodeURIComponent(scanId)}`)).scan;
        const rid = memo.scan?.releaseId ?? releaseId!;
        if (!memo.release || memo.release.releaseId !== rid) {
          memo.release = (await get<{ items: Release[] }>("releases")).items.find((item) => item.releaseId === rid) ?? null;
          if (!memo.release) throw Object.assign(new Error("릴리스를 찾을 수 없습니다."), { status: 404 });
        }
        if (!memo.policies) memo.policies = (await get<{ items: Policy[] }>("policies")).items;
        // A scan's round lives under that scan's policy; a release opened on its own is shown under the policy the site scans with.
        const viewPolicy = memo.scan?.policyHash ?? defaultPolicyOf(memo.policies)?.policyHash;
        const [votes, history] = await Promise.all([get<V3Votes>(votesPath(rid, viewPolicy)), get<{ items: HistoryItem[] }>(`releases/${encodeURIComponent(rid)}/history`)]);
        if (!scanId) {
          const round = shownRound(votes);
          if (round?.scanId && memo.scan?.scanId !== round.scanId) memo.scan = (await get<{ scan: Scan }>(`scans/${encodeURIComponent(round.scanId)}`)).scan;
        }
        if (!memo.registered || !memo.actions.length) {
          memo.actions = (await get<{ items: ChainAction[] }>("chain/actions")).items;
          memo.registered = memo.actions.some((item) => item.kind === "REGISTER_RELEASE" && item.releaseId === rid && item.status === "COMPLETED");
        }
        const round = shownRound(votes, scanId ?? undefined);
        const settled = Boolean(round && DECIDED.has(round.outcome)) || (!round && votes.status === "REVOKED");
        const policyHash = memo.scan?.policyHash ?? votes.policyHash;
        const disagrees = memo.admission !== null && memo.admission.status !== votes.status;
        if (settled && policyHash && (!memo.admission || (disagrees && memo.tries < 4 && Date.now() - memo.askedAt >= 2000))) {
          memo.askedAt = Date.now(); memo.tries += 1;
          memo.admission = await checkAdmission(memo.release, policyHash, signal);
        }
        const admissionPending = memo.admission !== null && memo.admission.status !== votes.status && memo.tries < 4;
        const at = Date.now();
        if (signal.aborted) return;
        setState({ loading: false, signedOut: false, notFound: false, error: "", release: memo.release, scan: memo.scan, votes, history: history.items, actions: memo.actions,
          policies: memo.policies, admission: memo.admission, admissionPending, at });
        const phase = progressPhase({ scanId: scanId ?? memo.scan?.scanId ?? "release", scan: memo.scan ?? ({ status: "COMPLETED", updatedAt: new Date(at).toISOString() } as Scan),
          votes, round, admission: memo.admission, admissionPending, now: at });
        if (poll) {
          if (phase === "done" || phase === "terminal" || phase === "error") return;
          timer = setTimeout(tick, phase === "stalled" ? 5000 : 1500);
        } else if (round?.outcome === "OPEN" || phase === "decided") timer = setTimeout(tick, 3000); // late votes, indexer lag or an admission recheck
      } catch (failure) {
        if (signal.aborted) return;
        const status = statusOf(failure);
        if (status === 401) { setState((previous) => ({ ...previous, loading: false, signedOut: true })); return; }
        if (status === 404) { setState((previous) => ({ ...previous, loading: false, notFound: true, error: messageOf(failure) })); return; }
        setState((previous) => ({ ...previous, loading: false, error: status && status >= 500 ? unreachable(status) : messageOf(failure) }));
        if (poll) timer = setTimeout(tick, 5000);
      }
    };
    void tick();
    return () => { controller.abort(); if (timer) clearTimeout(timer); };
  }, [signedIn, scanId, releaseId, poll, nonce]);
  const round = shownRound(state.votes, scanId ?? undefined);
  const flow = flowView({ release: state.release, scan: state.scan, votes: state.votes, round, history: state.history, actions: state.actions, admission: state.admission, admissionPending: state.admissionPending });
  const sessionError = session.status === "error" ? session.message : "";
  const phase: Phase = progressPhase({ scanId: scanId ?? (releaseId ? "release" : null), signedOut: session.status === "signed-out" || state.signedOut, notFound: state.notFound,
    failed: Boolean(sessionError || state.error),
    scan: scanId ? state.scan : (state.votes ? state.scan ?? ({ status: "COMPLETED", updatedAt: new Date(state.at).toISOString() } as Scan) : null),
    votes: state.votes, round, admission: state.admission, admissionPending: state.admissionPending, now: state.at || Date.now() });
  return { session, phase, ...state, error: state.error || sessionError, round, flow, refresh: () => setNonce((value) => value + 1) };
}
