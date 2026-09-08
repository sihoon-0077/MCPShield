import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";
// @ts-expect-error Shared pure Security commitment validation is ESM JavaScript.
import { validatePreparedReleaseBinding } from "../../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared canonical surface hash is ESM JavaScript.
import { toolSurfaceHash } from "../../gateway/src/artifact.mjs";

export function preparedDownload(payload: any, releaseId: string) {
  if (!payload || Object.keys(payload).sort().join() !== "binding,releaseId,schemaVersion,toolId,tools" ||
    payload.schemaVersion !== "mcpshield.gateway-prepared.v1" || payload.releaseId !== releaseId || !/^0x[a-f0-9]{64}$/.test(releaseId) ||
    !/^0x[a-f0-9]{64}$/.test(payload.toolId) || !validatePreparedReleaseBinding(payload.binding) || !Array.isArray(payload.tools) || payload.tools.length > 128 ||
    toolSurfaceHash(payload.tools) !== payload.binding.toolSurfaceHash || exactReleaseIdentity({ toolId: payload.toolId, ...payload.binding }).releaseId !== releaseId) throw Error("PREPARED_EXPORT_INVALID");
  const content = JSON.stringify(payload); if (Buffer.byteLength(content) > 1048576) throw Error("PREPARED_EXPORT_TOO_LARGE");
  return new Response(content, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store",
    "content-disposition": `attachment; filename="mcpshield-${releaseId}.json"`, "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'", "referrer-policy": "no-referrer", "cross-origin-resource-policy": "same-origin" } });
}
