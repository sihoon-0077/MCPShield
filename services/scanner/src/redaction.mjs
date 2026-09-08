export function redactPromptText(content) {
  return content
    .replace(/(https?:\/\/)[^\s/"']+:[^\s/@"']+@/gi, '$1[REDACTED_USERINFO]@')
    .replace(/([?&](?:token|key|secret|signature|sig|credential|authorization)=)[^&\s"']+/gi, '$1[REDACTED]')
    .replace(/-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_ACCESS_KEY]')
    .replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED_GCP_API_KEY]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, '[REDACTED_JWT]')
    .replace(/\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g, '[REDACTED_TOKEN]')
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+\/-]{12,}/gi, '$1[REDACTED]')
    .replace(/(["'])(password|passwd|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|private[_-]?key|authorization|credential)\1\s*:\s*(["'])([^\r\n]{4,}?)\3/gi,
      (_match, keyQuote, key, valueQuote) => `${keyQuote}${key}${keyQuote}:${valueQuote}[REDACTED]${valueQuote}`)
    .replace(/\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(['"])[^'"\r\n]{4,}\2/gi, '$1=$2[REDACTED]$2')
    .replace(/MCP_SHIELD_DEMO_CANARY_v1|CANARY::[A-Za-z0-9:_-]+/g, '[REDACTED_CANARY]');
}

export function redactEvidenceDocument(value, depth = 0, key = '') {
  if (depth > 64) throw new TypeError('evidence nesting exceeds limit');
  if (['input_tokens', 'output_tokens', 'total_tokens'].includes(key) && Number.isSafeInteger(value) && value >= 0) return value;
  if (/password|passwd|secret|token|api.?key|authorization|credential|private.?key/i.test(key) && !/hash|sha256|digest/i.test(key)) return '[REDACTED]';
  if (typeof value === 'string') return redactPromptText(value);
  if (Array.isArray(value)) return value.map((item) => redactEvidenceDocument(item, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactEvidenceDocument(item, depth + 1, name)]));
  return value;
}

export function sanitizeUntrustedEvidence(value, depth = 0, key = '') {
  if (/password|passwd|secret|token|api.?key|canary|authorization|credential|private.?key/i.test(key)) return '[REDACTED]';
  if (depth > 4) return '[TRUNCATED]';
  if (typeof value === 'string') return redactPromptText(value).slice(0, 512);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 32).map((item) => sanitizeUntrustedEvidence(item, depth + 1));
  if (value && typeof value === 'object') {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value).slice(0, 64)) {
      if (['__proto__', 'prototype', 'constructor'].includes(childKey)) continue;
      output[childKey.slice(0, 128)] = sanitizeUntrustedEvidence(childValue, depth + 1, childKey);
    }
    return output;
  }
  return String(value).slice(0, 128);
}
