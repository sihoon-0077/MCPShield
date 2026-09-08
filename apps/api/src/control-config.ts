import { resolve } from "node:path";
import type { ControlOptions } from "./control-plane.js";
import { v2ChainReader } from "./registry-v2-client.js";

export function controlConfig(env = process.env): ControlOptions | undefined {
  if (env.CONTROL_PLANE_ENABLED !== "true") return undefined;
  let credentials;
  try { credentials = JSON.parse(env.CONTROL_PLANE_CREDENTIALS ?? "[]"); } catch { throw new Error("CONTROL_PLANE_CREDENTIALS must be JSON"); }
  if (!Array.isArray(credentials) || !credentials.length) throw new Error("CONTROL_PLANE_CREDENTIALS required");
  if (!/^[0-9a-f]{64}$/.test(env.CONTROL_EVIDENCE_KEY ?? "")) throw new Error("CONTROL_EVIDENCE_KEY must be 32-byte hex");
  return {
    credentials,
    databaseUrl: env.CONTROL_DATABASE_URL ?? resolve("data/control-plane.sqlite"),
    artifactPath: env.CONTROL_ARTIFACT_PATH ?? resolve("data/control-artifacts"),
    evidencePath: env.CONTROL_EVIDENCE_PATH ?? resolve("data/control-evidence"),
    evidenceKey: env.CONTROL_EVIDENCE_KEY!,
    signingKey: env.CONTROL_SIGNING_KEY?.replace(/\\n/g, "\n"), signingKeyId: env.CONTROL_SIGNING_KEY_ID,
    chainDecision: env.CONTROL_V2_RPC_URLS ? v2ChainReader({ rpcUrls: env.CONTROL_V2_RPC_URLS.split(","),
      registryContract: env.CONTROL_V2_REGISTRY_ADDRESS ?? "", chainId: Number(env.CONTROL_V2_CHAIN_ID),
      confirmations: Number(env.CONTROL_V2_CONFIRMATIONS ?? "2") }) : undefined,
  };
}
