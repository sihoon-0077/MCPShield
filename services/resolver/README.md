# Artifact resolver and prepared-runtime preflight

The resolver verifies bounded npm archives and OCI blobs without executing them.
The existing self-contained v1 scanner/Gateway profile is unchanged.

## Implemented checkpoint: 1A (not generic execution)

`resolveArtifact()` now adds `metadata.runtimePreparation` for npm/local/tarball
and OCI sources. The result is always `status: INCONCLUSIVE`, `ready: false`,
`executionPerformed: false`; valid preflight is **not** a security pass.
No package installation, OCI process, image pull, or dependency download occurs
in preflight. Source acquisition remains the existing resolver's separate job.

`preflightNpmRuntime()` reuses the scanner's bounded, stable, no-symlink snapshot
and verifies its expected source tree digest before reading package metadata.
It selects an explicit `bin` (a name is required for multiple bins), rejects
absolute/aliased/traversing/Windows-special paths, and hashes the actual entrypoint
bytes. This initial Node profile accepts `.js`, `.cjs`, and `.mjs` bins, not
`npm start`, `npm run`, `npx`, shell scripts, or an inferred `main`/`index.js`.

Supplied lock v2/v3 must match package identity/declarations and contain exact
versions, canonical strong SHA-256/384/512 SRI, registry-only tarball URLs and
safe dependency paths. Missing/different coexisting locks, links, bundled
records, unsupported specs, weak/malformed SRI and missing direct dependencies
produce explicit issue codes. This is syntax/preflight validation only:
`archiveIntegrityVerified: false` and `graphVerifiedByNpm: false` remain false.
No tarball checksum or installed dependency closure is claimed from lock text.

The additive `mcpshield.prepared-runtime.v1` descriptor commits to source digest,
source tree digest, lock digest/origin, builder image digest, target platform,
final image digest, discovered tool surface hash, entrypoint bytes, exact argv
and isolation policy. Unknown values remain null. OCI lock origin is explicitly
`NOT_APPLICABLE`; missing npm lock origin is null, supplied is `SUPPLIED`, and
future isolated lock generation must use `RESOLVER_GENERATED`. The exported
`hashPreparedRuntimeDescriptor()` validates these distinctions and hashes
canonical JSON. It rejects forged READY stages and extra fields. A descriptor
hash is an identity commitment, never authorization to run.

Optional internal source fields are `binName`, `platform` and
`builderImageDigest`. Platform is explicitly Linux amd64/arm64 without variants;
ambiguous OCI platform matches are rejected. Public API/Gateway integration is
not added by this checkpoint. The fixed Node launch path in the descriptor is
the proposed future image layout, not a host executable.

For OCI, the verified image digest and observed Entrypoint+Cmd are bound as
container argv, not resolved as host paths. Their filesystem existence,
symlink semantics and generic process/file observation remain unverified.
Container-absolute argv is therefore retained as evidence but never executable
approval. Image-root users require review/non-root preparation. Raw source
documents/config/argv must stay in private artifact storage; do not log them
or expose unredacted resolver metadata as public evidence.

```powershell
node --import tsx --test tests/security/runtime-preflight.test.mjs tests/security/oci-resolver.test.mjs
```

## Next checkpoint: 1B, supplied-lock offline Node closure

1. Fetch only lock-pinned registry tarballs in a bounded acquisition step and
   verify every SRI; cap total bytes, packages and wall-clock budget. No package
   code executes on the host. Acquisition must not reuse the synthetic egress
   proxy as an Internet forward proxy.
2. Use a separately approved digest-pinned Node/npm builder container without
   network or host secrets/socket. Populate npm cache from verified bytes and
   run native `npm ci --ignore-scripts --offline --omit=dev --audit=false
   --fund=false`. Supply sanitized package/lock metadata in a fresh install
   directory; never consume package-owned `.npmrc` or lifecycle scripts.
   Let native npm validate the dependency graph instead of implementing a solver.
   See the [official npm ci contract](https://docs.npmjs.com/cli/v11/commands/npm-ci/)
   for lock requirements and the limits of `ignore-scripts`.
3. Create an immutable execution image containing the snapshot **and** installed
   dependencies. Do not use legacy v1's tree hash, which excludes node_modules,
   as the final execution identity. Bind builder, platform, selected launch
   descriptor, source/lock and final image digest.
4. Discover/pin the actual MCP surface in a fresh restricted runtime before
   registering a final release identity. Reuse the existing collector/sink;
   use the installed official SDK for a later language-neutral OCI collector.
5. Gateway must launch exactly the attested final image and descriptor, not
   reinstall or resolve a mutable tag. Missing graph/image/observation evidence
   remains INCONCLUSIVE. Cross-module identity/admission changes need Main review.

Later required stages, not completed here: lockless package resolution in an
isolated native solver with a registry-only acquisition broker; npm aliases,
bundled/native/script-requiring packages under an explicit policy; generic OCI
execution/observation and language-neutral stdio collector. Ordinary published
npm archives often lack a lock, so 1A/1B alone cannot satisfy generic FR001–003.
