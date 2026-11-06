import { createHash } from 'node:crypto';
import { canonicalJson } from './evidence.mjs';

export function toolSurfaceHash(tools) {
  const normalized = [...tools].sort((a, b) => {
    const left = `${String(a.name)}\0${canonicalJson(a)}`;
    const right = `${String(b.name)}\0${canonicalJson(b)}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return `0x${createHash('sha256').update(canonicalJson(normalized)).digest('hex')}`;
}


