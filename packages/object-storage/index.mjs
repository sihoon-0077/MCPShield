import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';

// This stores ciphertext only. Tenant-bound AES-GCM and report-root validation
// stay in the control plane; this adapter never grants public URLs or deletes.
export function createS3EvidenceStore({ bucket, region, endpoint, credentials, kmsKeyId,
  allowLoopbackHttp = false, timeoutMs = 5000, maxBytes = 32 * 1024 * 1024 }) {
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket ?? '') || !/^[a-z0-9-]{1,64}$/.test(region ?? '')) throw Error('S3_CONFIG_INVALID');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 28 || maxBytes > 128 * 1024 * 1024) throw Error('S3_LIMIT_INVALID');
  if (endpoint) {
    const url = new URL(endpoint);
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
        (url.protocol !== 'https:' && !(allowLoopbackHttp && url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)))) throw Error('S3_ENDPOINT_INVALID');
  }
  const client = new S3Client({ region, endpoint, credentials, forcePathStyle: Boolean(endpoint), maxAttempts: 2 });
  const objectKey = (key) => {
    if (!/^[a-f0-9]{64}$/.test(key)) throw Error('S3_KEY_INVALID');
    return `evidence/${key.slice(0, 2)}/${key}.bin`;
  };
  async function execute(command, read = false) {
    const controller = new AbortController();
    let stream;
    const stop = () => stream?.destroy(Error('S3_EVIDENCE_TIMEOUT'));
    controller.signal.addEventListener('abort', stop, { once: true });
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await client.send(command, { abortSignal: controller.signal });
      if (!read) return true;
      stream = response.Body;
      if (controller.signal.aborted) throw Error('S3_EVIDENCE_TIMEOUT');
      if (!stream || Number(response.ContentLength) > maxBytes) throw Error('S3_EVIDENCE_SIZE_INVALID');
      const chunks = []; let size = 0;
      for await (const chunk of stream) {
        size += chunk.length;
        if (size > maxBytes) throw Error('S3_EVIDENCE_SIZE_INVALID');
        chunks.push(chunk);
      }
      if (size < 28) throw Error('S3_EVIDENCE_SIZE_INVALID');
      return Buffer.concat(chunks);
    } catch (error) {
      if (controller.signal.aborted) throw Error('S3_EVIDENCE_TIMEOUT');
      if (!read && error.$metadata?.httpStatusCode === 412) return false;
      if (error.message === 'S3_EVIDENCE_SIZE_INVALID') throw error;
      throw Error('S3_EVIDENCE_UNAVAILABLE');
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener('abort', stop);
      stream?.destroy();
    }
  }
  return {
    async put(key, bytes) {
      if (!Buffer.isBuffer(bytes) || bytes.length < 28 || bytes.length > maxBytes) throw Error('S3_EVIDENCE_SIZE_INVALID');
      return execute(new PutObjectCommand({ Bucket: bucket, Key: objectKey(key), Body: bytes,
        ContentType: 'application/octet-stream', IfNoneMatch: '*', ChecksumAlgorithm: 'SHA256',
        ServerSideEncryption: kmsKeyId ? 'aws:kms' : 'AES256', ...(kmsKeyId ? { SSEKMSKeyId: kmsKeyId } : {}) }));
    },
    get(key) { return execute(new GetObjectCommand({ Bucket: bucket, Key: objectKey(key) }), true); },
    close() { client.destroy(); },
  };
}
