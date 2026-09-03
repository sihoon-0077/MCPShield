import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020Module, { type ErrorObject } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import type { ValidateFunction } from "ajv";
import type { ScanResult } from "../../../packages/protocol/api/types.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaRoot = path.resolve(here, "../../../packages/protocol/schemas");
const readSchema = (name: string) =>
  JSON.parse(fs.readFileSync(path.join(schemaRoot, name), "utf8"));

const Ajv2020 = Ajv2020Module as unknown as new (options: {
  allErrors: boolean;
  strict: boolean;
}) => any;
const addFormats = addFormatsModule as unknown as (ajv: any) => any;
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const findingSchema = readSchema("finding.schema.json");
const scanSchema = readSchema("scan-result.schema.json");
ajv.addSchema(findingSchema, "finding.schema.json");
const validate = ajv.compile(scanSchema) as ValidateFunction<ScanResult>;

export function validateScanResult(value: unknown):
  | { valid: true; value: ScanResult }
  | { valid: false; errors: ErrorObject[] } {
  return validate(value)
    ? { valid: true, value: value as ScanResult }
    : { valid: false, errors: validate.errors ?? [] };
}

export const patterns = {
  releaseId: /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/,
  artifactDigest: /^sha256:[0-9a-f]{64}$/,
  bytes32: /^0x[0-9a-f]{64}$/,
  address: /^0x[0-9a-fA-F]{40}$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
};
