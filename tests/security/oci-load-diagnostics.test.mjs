import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyOciLoadFailure } from '../../services/resolver/src/npm-closure.mjs';

test('native OCI loader failures expose only fixed categories, never daemon paths or archive text', () => {
  for (const suffix of ['manifest.json', 'blobs/json', 'oci-layout/json', 'index.json/json']) {
    assert.equal(classifyOciLoadFailure(`open /private/synthetic-token/${suffix}: no such file or directory`), 'OCI_NATIVE_LEGACY_ARCHIVE_LOADER');
  }
  assert.equal(classifyOciLoadFailure('private-tag: invalid reference format'), 'OCI_NATIVE_REFERENCE_REJECTED');
  assert.equal(classifyOciLoadFailure('unsupported media type private-source'), 'OCI_NATIVE_FORMAT_UNSUPPORTED');
  assert.equal(classifyOciLoadFailure('secret=synthetic-token; unspecified daemon error'), 'OCI_NATIVE_IMPORT_FAILED');
});
