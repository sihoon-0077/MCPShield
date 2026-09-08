import { isAbsolute, resolve } from "node:path";
// @ts-expect-error Shared scanner code identity helper; it reads installed bytes without Docker.
import { readOciObservationPolicy } from "../../../services/scanner/src/oci-observer.mjs";

export interface OciConfig {
  baseImageDigest: string; baseCatalogueDigest: string; trivyImageDigest: string; databaseDir: string; databaseDigest: string;
  sinkImageDigest: string; platform: { os: "linux"; architecture: "amd64" | "arm64" };
}
export function checkedOciConfig(value: OciConfig): OciConfig {
  const digests = ["baseImageDigest", "baseCatalogueDigest", "trivyImageDigest", "databaseDigest", "sinkImageDigest"] as const;
  if (!value || Object.keys(value).sort().join() !== [...digests, "databaseDir", "platform"].sort().join()
    || digests.some(key => !/^sha256:[a-f0-9]{64}$/.test(value[key])) || typeof value.databaseDir !== "string" || value.databaseDir.length > 2048
    || !isAbsolute(value.databaseDir) || !value.platform || Object.keys(value.platform).sort().join() !== "architecture,os"
    || value.platform.os !== "linux" || !["amd64", "arm64"].includes(value.platform.architecture)) throw new Error("INVALID_OCI_CONFIG");
  return { ...structuredClone(value), databaseDir: resolve(value.databaseDir) };
}
export async function ociTrust(config: OciConfig) {
  const local = checkedOciConfig(config), observation = await readOciObservationPolicy(local.sinkImageDigest);
  return { ...local, observerDigest: observation.collectorDigest, sinkCodeDigest: observation.sinkCodeDigest };
}
// This checks only the frozen operator configuration/installed code. A saved worker
// context is not an independent runtime proof; signers must acquire their own native evidence.
export async function checkedOciTrust(proof: any, config?: OciConfig) {
  if (!proof || !config) return undefined;
  const local = await ociTrust(config);
  if (["baseImageDigest", "baseCatalogueDigest", "trivyImageDigest", "databaseDigest", "sinkImageDigest", "observerDigest", "sinkCodeDigest"].some(key => proof.anchors?.[key] !== local[key as keyof typeof local])
    || proof.platform?.os !== local.platform.os || proof.platform?.architecture !== local.platform.architecture) return undefined;
  return proof;
}
