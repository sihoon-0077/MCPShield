// JCS-compatible for parsed JSON: sort UTF-16 keys, retain string bytes (no NFC rewrite).
// Pure shared serializer: browser policy validation and server evidence use identical bytes.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${canonicalJson(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('canonical JSON requires finite numbers');
  if (typeof value === 'string' && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) throw new TypeError('canonical JSON rejects lone Unicode surrogates');
  const json = JSON.stringify(value);
  if (json === undefined) throw new TypeError('canonical JSON cannot contain undefined');
  return json;
}
