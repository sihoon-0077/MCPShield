import type { S3ClientConfig } from '@aws-sdk/client-s3';
export interface EvidenceObjectStore {
  put(key: string, ciphertext: Buffer): Promise<boolean>;
  get(key: string): Promise<Buffer>;
  close(): void;
}
export function createS3EvidenceStore(options: {
  bucket: string; region: string; endpoint?: string; credentials?: S3ClientConfig['credentials'];
  kmsKeyId?: string; allowLoopbackHttp?: boolean; timeoutMs?: number; maxBytes?: number;
}): EvidenceObjectStore;
