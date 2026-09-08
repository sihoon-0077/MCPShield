// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ValidatorRegistry {
    address public immutable owner;
    uint32 public version = 1;
    address[3] public validators;
    address[3] private pending;
    uint64 public rotationAt;
    mapping(address => bool) public disabled;
    event RotationScheduled(uint64 effectiveAt);
    event ValidatorSetRotated(uint32 version, address[3] validators);
    event ValidatorDisabled(address validator, uint32 version);
    modifier onlyOwner() { require(msg.sender == owner, "ONLY_OWNER"); _; }
    constructor(address admin, address[3] memory initial) {
        require(admin != address(0), "INVALID_ADMIN");
        owner = admin;
        _validate(initial);
        validators = initial;
    }
    function _validate(address[3] memory values) private pure {
        require(values[0] != address(0) && values[1] != address(0) && values[2] != address(0)
            && values[0] != values[1] && values[0] != values[2] && values[1] != values[2], "INVALID_SET");
    }
    function isActiveValidator(address account, uint32 setVersion) public view returns (bool) {
        return setVersion == version && !disabled[account]
            && (account == validators[0] || account == validators[1] || account == validators[2]);
    }
    function scheduleRotation(address[3] calldata next) external onlyOwner {
        _validate(next);
        pending = next;
        rotationAt = uint64(block.timestamp + 1 days);
        emit RotationScheduled(rotationAt);
    }
    function rotate() external {
        require(rotationAt != 0 && block.timestamp >= rotationAt, "TIMELOCK");
        validators = pending;
        rotationAt = 0;
        ++version;
        // Disabled compromised keys stay disabled even if mistakenly re-added.
        emit ValidatorSetRotated(version, validators);
    }
    function disable(address account) external onlyOwner {
        require(isActiveValidator(account, version), "NOT_ACTIVE");
        disabled[account] = true;
        ++version;
        emit ValidatorDisabled(account, version);
    }
}

contract PolicyRegistry {
    address public immutable owner;
    struct Policy { bytes32 documentDigest; uint64 publishedAt; bool deprecated; }
    mapping(bytes32 => Policy) public policies;
    event PolicyPublished(bytes32 indexed policyHash, bytes32 documentDigest);
    event PolicyDeprecated(bytes32 indexed policyHash);
    modifier onlyOwner() { require(msg.sender == owner, "ONLY_OWNER"); _; }
    constructor(address admin) { require(admin != address(0), "INVALID_ADMIN"); owner = admin; }
    function publish(bytes32 policyHash, bytes32 documentDigest) external onlyOwner {
        require(policyHash != bytes32(0) && documentDigest != bytes32(0), "EMPTY_HASH");
        require(policies[policyHash].publishedAt == 0, "IMMUTABLE_POLICY");
        policies[policyHash] = Policy(documentDigest, uint64(block.timestamp), false);
        emit PolicyPublished(policyHash, documentDigest);
    }
    function deprecate(bytes32 policyHash) external onlyOwner {
        require(policies[policyHash].publishedAt != 0, "UNKNOWN_POLICY");
        policies[policyHash].deprecated = true;
        emit PolicyDeprecated(policyHash);
    }
    function active(bytes32 policyHash) external view returns (bool) {
        Policy memory policy = policies[policyHash];
        return policy.publishedAt != 0 && !policy.deprecated;
    }
}

/// Exact-byte identities and policy-scoped attestations. V1 stays deployable unchanged.
contract ReleaseRegistryV2 {
    enum Status { UNVERIFIED, VERIFIED, QUARANTINED, REVOKED, EXPIRED }
    enum Verdict { PASS, FAIL, ABSTAIN }
    struct Identity { bytes32 toolId; bytes32 artifactDigest; bytes32 manifestDigest; bytes32 toolSurfaceDigest; bool exists; }
    struct Attestation {
        bytes32 releaseId; bytes32 artifactDigest; bytes32 manifestDigest; bytes32 toolSurfaceDigest;
        bytes32 policyHash; bytes32 reportRoot; uint8 verdict; uint64 validFrom; uint64 validUntil;
        uint32 validatorSetVersion; uint256 nonce; uint256 deadline;
    }
    struct Decision {
        bytes32 reportRoot; uint64 validFrom; uint64 validUntil; uint64 quarantineUntil;
        uint32 validatorSetVersion; uint8 approvals; uint8 rejections; Status status;
    }
    address public immutable owner;
    ValidatorRegistry public immutable validators;
    PolicyRegistry public immutable policies;
    mapping(bytes32 => Identity) public releases;
    mapping(bytes32 => mapping(bytes32 => Decision)) private decisions;
    mapping(bytes32 => bool) public revoked;
    mapping(bytes32 => mapping(address => bool)) public voted;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedDigest;
    mapping(bytes32 => uint64) public quarantinedAt;
    mapping(bytes32 => uint64) public quarantineUntil;
    bytes32 private constant TYPEHASH = keccak256("Attestation(bytes32 releaseId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bytes32 policyHash,bytes32 reportRoot,uint8 verdict,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion,uint256 nonce,uint256 deadline)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 public constant CANARY_EXFILTRATION = keccak256("CANARY_EXFILTRATION");
    bytes32 public constant HOST_ESCAPE_ATTEMPT = keccak256("HOST_ESCAPE_ATTEMPT");
    bytes32 public constant DIGEST_MISMATCH = keccak256("DIGEST_MISMATCH");
    event ReleaseRegistered(bytes32 indexed releaseId, bytes32 indexed toolId, bytes32 artifactDigest, bytes32 manifestDigest, bytes32 toolSurfaceDigest);
    event AttestationAccepted(bytes32 indexed releaseId, address indexed validator, bytes32 indexed policyHash, uint8 verdict, bytes32 reportRoot, uint64 validUntil);
    event ReleaseStatusChanged(bytes32 indexed releaseId, bytes32 indexed policyHash, Status previousStatus, Status newStatus, bytes32 reasonCode, bytes32 evidenceRoot);
    constructor(address admin, ValidatorRegistry validatorRegistry, PolicyRegistry policyRegistry) {
        require(admin != address(0) && address(validatorRegistry) != address(0) && address(policyRegistry) != address(0), "INVALID_CONFIG");
        owner = admin; validators = validatorRegistry; policies = policyRegistry;
    }
    function registerRelease(bytes32 toolId, bytes32 artifact, bytes32 manifest, bytes32 surface) external returns (bytes32 key) {
        require(msg.sender == owner, "ONLY_OWNER");
        require(toolId != bytes32(0) && artifact != bytes32(0) && manifest != bytes32(0) && surface != bytes32(0), "EMPTY_HASH");
        key = keccak256(abi.encode(toolId, artifact, manifest, surface));
        require(!releases[key].exists, "ALREADY_REGISTERED");
        releases[key] = Identity(toolId, artifact, manifest, surface, true);
        emit ReleaseRegistered(key, toolId, artifact, manifest, surface);
    }
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("MCPShieldReleaseRegistry"), keccak256("1"), block.chainid, address(this)));
    }
    function attestationDigest(Attestation calldata a) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(TYPEHASH, a))));
    }
    function submitAttestation(Attestation calldata a, bytes calldata signature) external {
        Identity memory identity = releases[a.releaseId];
        require(identity.exists && identity.artifactDigest == a.artifactDigest && identity.manifestDigest == a.manifestDigest
            && identity.toolSurfaceDigest == a.toolSurfaceDigest, "IDENTITY_MISMATCH");
        require(!revoked[a.releaseId], "TERMINAL_RELEASE");
        require(block.timestamp <= a.deadline && a.validFrom <= block.timestamp && a.validUntil > block.timestamp
            && a.validUntil > a.validFrom && a.validUntil <= a.validFrom + 30 days, "EXPIRED_OR_INVALID_VALIDITY");
        require(policies.active(a.policyHash), "INACTIVE_POLICY");
        require(a.reportRoot != bytes32(0) && a.verdict <= uint8(Verdict.ABSTAIN), "INVALID_VERDICT");
        require(a.validatorSetVersion == validators.version(), "STALE_VALIDATOR_SET");
        bytes32 digest = attestationDigest(a);
        address signer = _recover(digest, signature);
        require(validators.isActiveValidator(signer, a.validatorSetVersion), "NOT_VALIDATOR");
        bytes32 signedDigest = keccak256(abi.encode(digest, signer));
        require(!usedDigest[signedDigest] && a.nonce == nonces[signer], "REPLAY");
        bytes32 round = keccak256(abi.encode(a.releaseId, a.policyHash, a.reportRoot, a.validFrom, a.validUntil, a.validatorSetVersion));
        require(!voted[round][signer], "DUPLICATE_VOTE");
        Decision storage d = decisions[a.releaseId][a.policyHash];
        // A new report cannot steal votes or replace a live round before its deadline.
        if (d.reportRoot != a.reportRoot || d.validFrom != a.validFrom || d.validUntil != a.validUntil || d.validatorSetVersion != a.validatorSetVersion) {
            require(d.validUntil <= block.timestamp || d.validatorSetVersion != a.validatorSetVersion
                || (quarantinedAt[a.releaseId] != 0 && a.validFrom > quarantinedAt[a.releaseId]), "ROUND_IN_PROGRESS");
            d.reportRoot = a.reportRoot; d.validFrom = a.validFrom; d.validUntil = a.validUntil;
            d.validatorSetVersion = a.validatorSetVersion; d.approvals = 0; d.rejections = 0;
            _transition(a.releaseId, a.policyHash, d, Status.UNVERIFIED, keccak256("FRESH_SCAN"));
        }
        usedDigest[signedDigest] = true; nonces[signer] = a.nonce + 1; voted[round][signer] = true;
        if (a.verdict == uint8(Verdict.PASS)) ++d.approvals;
        if (a.verdict == uint8(Verdict.FAIL)) ++d.rejections;
        emit AttestationAccepted(a.releaseId, signer, a.policyHash, a.verdict, a.reportRoot, a.validUntil);
        if (d.rejections >= 2) {
            revoked[a.releaseId] = true;
            _transition(a.releaseId, a.policyHash, d, Status.REVOKED, keccak256("FAIL_QUORUM"));
        } else if (d.approvals >= 2 && d.rejections == 0 && quarantineUntil[a.releaseId] <= block.timestamp
            && (quarantinedAt[a.releaseId] == 0 || a.validFrom > quarantinedAt[a.releaseId])) {
            _transition(a.releaseId, a.policyHash, d, Status.VERIFIED, keccak256("PASS_QUORUM"));
        }
    }
    function quarantine(bytes32 releaseId, bytes32 policyHash, bytes32 evidenceHash, bytes32 reasonCode, uint64 expiresAt) external {
        require(validators.isActiveValidator(msg.sender, validators.version()), "NOT_VALIDATOR");
        require(releases[releaseId].exists && !revoked[releaseId], "INVALID_RELEASE");
        require(policies.active(policyHash) && evidenceHash != bytes32(0), "INVALID_EVIDENCE");
        require(reasonCode == CANARY_EXFILTRATION || reasonCode == HOST_ESCAPE_ATTEMPT || reasonCode == DIGEST_MISMATCH, "NON_DETERMINISTIC_REASON");
        require(expiresAt > block.timestamp && expiresAt <= block.timestamp + 1 days, "INVALID_TTL");
        Decision storage d = decisions[releaseId][policyHash];
        require(quarantineUntil[releaseId] <= block.timestamp, "ALREADY_QUARANTINED");
        d.quarantineUntil = expiresAt; quarantinedAt[releaseId] = uint64(block.timestamp);
        quarantineUntil[releaseId] = expiresAt;
        Status previous = d.status; d.status = Status.QUARANTINED;
        emit ReleaseStatusChanged(releaseId, policyHash, previous, Status.QUARANTINED, reasonCode, evidenceHash);
    }
    function getDecision(bytes32 releaseId, bytes32 policyHash) public view returns (Decision memory d) {
        require(releases[releaseId].exists, "UNKNOWN_RELEASE");
        d = decisions[releaseId][policyHash];
        if (revoked[releaseId]) d.status = Status.REVOKED;
        else if (quarantineUntil[releaseId] > block.timestamp) d.status = Status.QUARANTINED;
        else if (d.status == Status.QUARANTINED || (d.validUntil != 0 && d.validUntil <= block.timestamp)
            || (quarantinedAt[releaseId] != 0 && d.validFrom <= quarantinedAt[releaseId])
            || (d.status == Status.VERIFIED && (d.validatorSetVersion != validators.version() || !policies.active(policyHash)))) d.status = Status.EXPIRED;
    }
    function syncExpiry(bytes32 releaseId, bytes32 policyHash) external {
        Decision memory effective = getDecision(releaseId, policyHash);
        Decision storage stored = decisions[releaseId][policyHash];
        if (effective.status != stored.status) _transition(releaseId, policyHash, stored, effective.status, keccak256("EXPIRY"));
    }
    function _transition(bytes32 releaseId, bytes32 policyHash, Decision storage d, Status next, bytes32 reason) private {
        if (d.status == next) return;
        Status previous = d.status; d.status = next;
        emit ReleaseStatusChanged(releaseId, policyHash, previous, next, reason, d.reportRoot);
    }
    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        require(signature.length == 65, "INVALID_SIGNATURE");
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
        require(uint256(s) <= HALF_N && (v == 27 || v == 28), "INVALID_SIGNATURE");
        signer = ecrecover(digest, v, r, s); require(signer != address(0), "INVALID_SIGNATURE");
    }
}
