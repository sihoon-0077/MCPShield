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
isolated lock generation uses `RESOLVER_GENERATED`. The exported
`hashPreparedRuntimeDescriptor()` validates these distinctions and hashes
canonical JSON. It rejects forged READY stages and extra fields. The additive
`CLOSURE_PREPARED` stage requires a verified supplied/generated lock, builder, platform, entrypoint
and final image identity; it still cannot grant READY. A descriptor
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

## Implemented checkpoint: 1B, supplied-lock offline Node closure

`acquireNpmClosure()` validates actual archive SRI and archive package identity,
reuses the no-links/path-bounded tar resolver, and limits total compressed and
expanded bytes, files and deadline. Repeated dependency locations count against
the expanded quota even when they reuse one cached tar. Its returned input
directory is private, read-only data; call its `cleanup()` when finished.

`prepareNpmClosure()` additionally requires Linux Docker and an operator-supplied
exact builder **image config ID**. Missing settings return NOT_RUN/INCONCLUSIVE,
never READY. A separate approved toolchain image uses the pinned official Node
22 Alpine amd64 base, upgraded OpenSSL libraries, and npm 12.0.2 verified against
the official npm tarball SRI. Candidate input is never present during this
network-enabled trusted builder build. CI must vulnerability-scan the resulting
builder ID before approving it; no clean vulnerability result is implied here.
The toolchain additionally replaces npm's vulnerable bundled brace-expansion,
ip-address and tar with SRI-verified 5.0.9, 10.3.1 and 7.5.22 archives. Only native
tar extraction runs for these three replacements: no dependency solver, lifecycle
script or dev/audit install. The patch-set label and installed versions are checked
before candidate preparation; an unpatched npm 12.0.2 image is refused.

The installer has no network, capabilities, host secrets or Docker socket; it
runs as UID/GID 1000 with a read-only root filesystem, memory/pid/CPU limits,
bounded tmpfs and a task-owned Docker volume. It does not load package `.npmrc`,
uses offline npm cache data, disables lifecycle scripts and bin links, and hashes
every installed file including node_modules. Candidate code is not invoked.
The returned Docker tar is validated again (paths, links, permissions, bytes and
hashes) without host extraction/execution before native Docker ADD builds the
final image. npm/daemon stderr is discarded, not exposed as evidence.

On success the result remains `status: INCONCLUSIVE`, `ready: false` and
`phase: CLOSURE_PREPARED`. `imageDigestKind: DOCKER_IMAGE_CONFIG_ID` distinguishes
local immutable image IDs from a not-yet-published OCI registry manifest digest.
The descriptor binds that ID and exact argv. `cleanup()` removes the uniquely
tagged output image; temporary containers, volumes and inputs are already cleaned.
Real MCP discovery, runtime observation, release registration and Gateway launch
binding are still separate required stages.

Linux CI/operator setup (trusted builder only; no candidate package execution):

```sh
docker build -f services/resolver/Dockerfile.builder -t mcpshield-runtime-builder:reviewed .
export MCPSHIELD_RUNTIME_BUILDER_IMAGE=$(docker image inspect mcpshield-runtime-builder:reviewed --format '{{.Id}}')
# Scan/approve this exact image ID before enabling the actual test.
MCPSHIELD_DOCKER_TESTS=1 node --import tsx --test tests/security/npm-closure.test.mjs
```

The actual Docker regression uses only authored synthetic package bytes, verifies
the dependency can be imported inside the resulting restricted image, and checks
that lifecycle hooks, package npmrc, rootfs writes and external networking are
disabled. Without the explicit builder configuration that test is skipped, not
reported as measured success. Default portable checks still cover real archive
integrity, timeout, dependency hash changes and malicious tar boundaries.

### Pipeline and next integration

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

Later required stages, not completed here: npm aliases,
bundled/native/script-requiring packages under an explicit policy; generic OCI
execution/observation and language-neutral stdio collector. Ordinary published
npm archives often lack a lock, so 1A/1B alone cannot satisfy generic FR001–003.

### Generated-lock contract

The internal `preflightNpmRuntime`/`acquireNpmClosure` options also accept a
`generatedLock: Buffer` of at most 1 MiB. This is server-owned solver output,
never a public API field or a substitute for actually running the isolated
solver. It receives the same strict package/dependency/SRI/registry validation
as a supplied lock and uses `lockOrigin: RESOLVER_GENERATED`. A supplied and
generated lock cannot coexist, even if their bytes match.

The source snapshot/tree digest is verified **before** adding this separately
committed lock to the private acquisition input. Original caller/source files
are never changed. The generated lock participates in final closure bytes and
the descriptor lock digest, while original source identity stays immutable.
Local paths, workspaces, Git/URL/alias dependency specs, overrides and bundled
layouts are explicitly rejected before a native solver would start. Unsupported
cases remain INCONCLUSIVE rather than falling back to host npm execution.

### Isolated native generation for published packages without a lock

`generateNpmLock()` runs the approved builder's native `npm install
--package-lock-only --ignore-scripts --ignore-extension` in a fresh, non-root,
read-only Docker container. Only the verified `package.json` is mounted; source,
package `.npmrc`, npm extensions, host environment and secrets are absent. Distinct
blank user/global config files, fixed registry, disabled Git executable and native
file/directory/Git/remote dependency restrictions are enforced. No node_modules
installation is permitted during generation. The original archive/tree is never
changed; the resulting lock is validated again through strict preflight.

The solver has an internal-only network, loopback DNS and a static address for a
separate authenticated metadata broker. Only that trusted broker has Internet
egress. It accepts canonical npm package-name GETs, not arbitrary URLs, tarball
paths, CONNECT or body forwarding. External requests use fixed registry HTTPS,
no redirects or forwarded credentials. Bounds are 8 seconds per response, 90
seconds per broker job, 4 MiB per response, 32 MiB total, 128 cached packages,
256 requests and 16 concurrent requests. Evidence retains response/package-name
hashes, sizes and collection times, never token or metadata body contents.

The trusted broker and solver scripts are part of the builder image config ID;
`io.mcpshield.lock-generator=npm-package-lock-only-v1` is required. Rebuild and
vulnerability-scan the exact new builder ID before approving this path. Generation
returns `LOCK_GENERATED/INCONCLUSIVE`, not READY or scan PASS. The full
`prepareAndScanRuntime()` wrapper handles missing-lock generation, verified tar
acquisition, network-none installation, final-image discovery and full scanning.
Its encrypted bundle adds digest-only `prepared/lock-generation.json` provenance.

The Linux `npm-closure.test.mjs` test above additionally exercises actual native
lock generation against **authored synthetic registry metadata**, then installs
verified synthetic tar bytes offline. This checks real Docker/npm isolation but
does not claim a live public-registry or commercial-model measurement. Portable
`registry-broker.test.mjs` checks canonical routes, auth/header isolation, cache,
size rejection and an actual stalled HTTP body deadline. Missing Docker/builder
configuration remains NOT_RUN/INCONCLUSIVE; unsupported dependency layouts remain
explicitly rejected. npm behavior follows the [package-lock-only contract](https://docs.npmjs.com/cli/v11/commands/npm-install/)
and [native npm configuration](https://docs.npmjs.com/using-npm/config/).

## OCI 2A: native import and language-neutral observation (not approval)

`importOciRuntime({root, sourceTreeDigest, platform})` accepts the resolver-owned
artifact with an `oci/` layout. It re-verifies the original stable snapshot,
selected raw manifest/config/layer hashes, decompressed layer diff IDs and an
explicit expansion budget before calling native `docker image load`. Docker
alone applies layers and whiteouts. Candidate files are never extracted or run
on the host; no custom OCI layer application or external importer is used.
Engines without OCI layout loading return `NOT_RUN/INCONCLUSIVE`.

Only the selected image enters a sanitized single-manifest import index with a
task-unique tag; candidate tag annotations cannot overwrite local tags. Already
present exact config IDs are independently inspected without taking ownership.
Cleanup removes only task-owned tags/containers/networks, not broad image stores.
An unstarted Docker export verifies the final filesystem and selected executable.
`sha256-canonical-oci-rootfs-v1` hashes sorted path/type/mode/uid/gid/content/link
records, not nondeterministic tar timestamps/order. Link traversal is confined
to immutable image paths and limited to 32 hops; PATH-based entrypoints are not
guessed. Candidate image volumes, on-build actions and unsafe environment keys
are refused; healthchecks are disabled. LD_PRELOAD, NODE_OPTIONS, PYTHONPATH,
HOME and credential environment variables do not enter this profile.

The separate `mcpshield.oci-runtime.v1` / `oci-container-v1` descriptor commits to
the original tree/index/manifest/config digests, final Docker config ID, platform,
canonical rootfs, requested/resolved executable and link-chain digests, argv,
working directory, original whitelisted environment digest and fixed synthetic
execution policy. `IMPORTED` has a null MCP surface; `OBSERVED` has the actual
full surface hash. Neither stage means READY or grants a signed release.
The existing npm descriptor, original fixture identities and npm PASS policy
are unchanged.

`observeOciRuntime()` uses the installed official MCP client **outside** the
candidate container. It speaks stdio to `docker start -ai` with bounded frames,
total traffic, pages, calls and deadlines. It does not inject Node or hooks into
the image, enable sampling/roots/elicitation handlers, compile candidate output
schemas, or reuse host credentials. Every discovery/normal/adversarial step gets
a fresh non-root read-only container, capability/pid/CPU/memory limits, internal
network and eight synthetic canaries. A separate approved sink image records
hash-only effects. Proxy requests accept standard synthetic Basic credentials as
well as Bearer; the events API remains Bearer-only.

Successful protocol/call collection is `COMPLETED_LIMITED_OCI_PROFILE`, while
approval remains `ABSTAIN`, `ready:false`, filesystem reads `NOT_OBSERVED`, and
binary semantics `NOT_REVIEWED`. Independent canary effects can report FAILED;
their absence cannot grant PASS. Raw tool metadata/descriptors belong only in
encrypted operator evidence, never public reports. The execution evidence binds
trusted external collector source, sink source and approved sink image ID.

Portable checks:

```sh
node --import tsx --test tests/security/oci-runtime.test.mjs tests/security/egress-proxy.test.mjs
```

The opt-in Linux test uses **authored synthetic** BusyBox/shell MCP code with no
Node interpreter. It obtains BusyBox/musl bytes through a never-started existing
approved CI builder, imports a scratch OCI image, verifies a symlinked absolute
entrypoint, two-page tools/list, normal calls and synthetic canary exfiltration.
No extra external image download or host binary execution is necessary.

```sh
MCPSHIELD_DOCKER_TESTS=1 node --import tsx --test tests/security/oci-runtime.test.mjs
```

Required setting: `MCPSHIELD_RUNTIME_BUILDER_IMAGE` is the operator-approved
Linux amd64 builder config ID. No actual Docker result is claimed when unset.
This checkpoint retains the original 16 MiB artifact snapshot boundary and caps
cumulative decompressed layer archives/export tar at 160 MiB, final data at
128 MiB and final entries at 20,000. **Still required for the full master**:
additive 100 MiB OCI source identity/budget profile, 512 MiB cumulative expansion
and export / 50,000 file limits, filesystem and SBOM/binary review, independent
OCI signing policy, and Gateway integration. These omissions are not npm-policy
PASS substitutions. Relevant native contracts: [Docker load](https://docs.docker.com/reference/cli/docker/image/load/)
and [OCI image configuration](https://specs.opencontainers.org/image-spec/config/).
