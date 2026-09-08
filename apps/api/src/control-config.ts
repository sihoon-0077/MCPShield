import { resolve } from "node:path";
import type { ControlOptions } from "./control-plane.js";
import { v2ChainReader } from "./registry-v2-client.js";
import { V2Relayer } from "./chain-outbox.js";
import { createS3EvidenceStore } from "../../../packages/object-storage/index.mjs";

export function controlConfig(env = process.env): ControlOptions | undefined {
  if (env.CONTROL_PLANE_ENABLED !== "true") return undefined;
  let credentials;
  try { credentials = JSON.parse(env.CONTROL_PLANE_CREDENTIALS ?? "[]"); } catch { throw new Error("CONTROL_PLANE_CREDENTIALS must be JSON"); }
  if (!Array.isArray(credentials) || !credentials.length) throw new Error("CONTROL_PLANE_CREDENTIALS required");
  if (!/^[0-9a-f]{64}$/.test(env.CONTROL_EVIDENCE_KEY ?? "")) throw new Error("CONTROL_EVIDENCE_KEY must be 32-byte hex");
  const allowRemoteAi = env.CONTROL_ALLOW_REMOTE_AI === "true";
  const aiProvider = env.CONTROL_AI_PROVIDER ?? "custom", aiTimeoutMs = Number(env.CONTROL_AI_TIMEOUT_MS ?? 45000);
  if (!["custom", "openai"].includes(aiProvider) || !Number.isSafeInteger(aiTimeoutMs) || aiTimeoutMs < 100 || aiTimeoutMs > 120000) throw new Error("INVALID_CONTROL_AI_CONFIG");
  const aiToken = env.CONTROL_AI_TOKEN ?? (aiProvider === "openai" ? env.OPENAI_API_KEY : undefined);
  if (allowRemoteAi && aiProvider === "openai" && (!aiToken || !env.CONTROL_AI_MODEL)) throw new Error("CONTROL_OPENAI_KEY_AND_MODEL_REQUIRED");
  if (allowRemoteAi && aiProvider === "custom" && !env.CONTROL_AI_URL) throw new Error("CONTROL_AI_URL_REQUIRED");
  if (allowRemoteAi && env.CONTROL_AI_URL) {
    const url = new URL(env.CONTROL_AI_URL);
    if (url.username || url.password || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) throw new Error("CONTROL_AI_HTTPS_REQUIRED");
  }
  return {
    credentials,
    databaseUrl: env.CONTROL_DATABASE_URL ?? resolve("data/control-plane.sqlite"),
    artifactPath: env.CONTROL_ARTIFACT_PATH ?? resolve("data/control-artifacts"),
    evidencePath: env.CONTROL_EVIDENCE_PATH ?? resolve("data/control-evidence"),
    evidenceKey: env.CONTROL_EVIDENCE_KEY!,
    evidenceStore: env.CONTROL_S3_BUCKET ? createS3EvidenceStore({ bucket: env.CONTROL_S3_BUCKET,
      region: env.CONTROL_S3_REGION ?? "", endpoint: env.CONTROL_S3_ENDPOINT,
      kmsKeyId: env.CONTROL_S3_KMS_KEY_ID, allowLoopbackHttp: env.CONTROL_S3_ALLOW_LOOPBACK_HTTP === "true" }) : undefined,
    signingKey: env.CONTROL_SIGNING_KEY?.replace(/\\n/g, "\n"), signingKeyId: env.CONTROL_SIGNING_KEY_ID,
    scannerOptions: { sandbox: env.CONTROL_SANDBOX_MODE === "docker" ? "docker" : undefined, allowRemoteAi,
      ...(allowRemoteAi ? { aiProvider: aiProvider as "custom" | "openai", aiModel: env.CONTROL_AI_MODEL, aiUrl: env.CONTROL_AI_URL, aiToken, aiTimeoutMs } : {}) },
    chainDecision: env.CONTROL_V2_RPC_URLS ? v2ChainReader({ rpcUrls: env.CONTROL_V2_RPC_URLS.split(","),
      registryContract: env.CONTROL_V2_REGISTRY_ADDRESS ?? "", chainId: Number(env.CONTROL_V2_CHAIN_ID),
      confirmations: Number(env.CONTROL_V2_CONFIRMATIONS ?? "2") }) : undefined,
    v2Relayer: env.CONTROL_V2_RELAYER_KEY && env.CONTROL_V2_RPC_URLS ? new V2Relayer(env.CONTROL_V2_RPC_URLS.split(",")[0], env.CONTROL_V2_REGISTRY_ADDRESS ?? "", Number(env.CONTROL_V2_CHAIN_ID), env.CONTROL_V2_RELAYER_KEY) : undefined,
  };
}
