import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_ROOT = resolve(HERE, '../../../packages/protocol/schemas');
const readSchema = (name) => JSON.parse(readFileSync(resolve(SCHEMA_ROOT, name), 'utf8'));

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(readSchema('finding.schema.json'), 'finding.schema.json');
const validateScanResult = ajv.compile(readSchema('scan-result.schema.json'));

export function assertCanonicalScanResult(value) {
  if (validateScanResult(value)) return value;
  const summary = (validateScanResult.errors ?? [])
    .map(({ instancePath, message }) => `${instancePath || '/'} ${message}`)
    .join('; ');
  throw new TypeError(`scan result violates canonical protocol schema: ${summary}`);
}
