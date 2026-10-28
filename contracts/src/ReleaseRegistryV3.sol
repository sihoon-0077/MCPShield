// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ValidatorRegistry, PolicyRegistry } from "./ReleaseRegistryV2.sol";

/// ADR-008. Each validator signs its own evidence hash, every vote (dissent included) stays on chain,
/// and a round that all three validators voted on without a 2-of-3 result goes to human review.
/// A round is (release, policy, validity window, validator set) and never includes a report, so
/// independent scans count toward one quorum. Opening or voting in a round never touches the live decision;
/// only a decided round can replace it. The read surface (releases, getDecision, validators, policies)
/// matches ReleaseRegistryV2, so a Gateway only changes the registry address. V2 stays deployable unchanged.
contract ReleaseRegistryV3 {
    enum Status { UNVERIFIED, VERIFIED, QUARANTINED, REVOKED, EXPIRED }
    enum Verdict { PASS, FAIL, ABSTAIN }
    enum Outcome { OPEN, APPROVED, REJECTED, SPLIT }
    struct Identity { bytes32 toolId; bytes32 artifactDigest; bytes32 manifestDigest; bytes32 toolSurfaceDigest; bool exists; }
    struct Attestation {
        bytes32 releaseId; bytes32 artifactDigest; bytes32 manifestDigest; bytes32 toolSurfaceDigest;
        bytes32 policyHash; bytes32 evidenceHash; uint8 verdict; uint64 validFrom; uint64 validUntil;
        uint32 validatorSetVersion; uint256 nonce; uint256 deadline;
    }
    struct Round {
        bytes32 releaseId; bytes32 policyHash; uint64 validFrom; uint64 validUntil; uint32 validatorSetVersion;
        uint8 approvals; uint8 rejections; uint8 abstentions; Outcome outcome; uint64 openedAt; uint64 decidedAt;
    }
    struct Vote { bool cast; uint8 verdict; bytes32 evidenceHash; }
    /// Same layout as ReleaseRegistryV2.Decision. reportRoot carries the id of the round behind the decision.
    struct Decision {
        bytes32 reportRoot; uint64 validFrom; uint64 validUntil; uint64 quarantineUntil;
        uint32 validatorSetVersion; uint8 approvals; uint8 rejections; Status status;
    }
    struct Quarantine { bytes32 releaseId; bytes32 policyHash; bytes32 evidenceHash; bytes32 reasonCode; uint64 expiresAt; uint32 validatorSetVersion; uint256 nonce; uint256 deadline; }
    address public immutable owner;
    ValidatorRegistry public immutable validators;
    PolicyRegistry public immutable policies;
    mapping(bytes32 => Identity) public releases;
    mapping(bytes32 => Round) private rounds;
    mapping(bytes32 => mapping(address => Vote)) private votes;
    mapping(bytes32 => mapping(bytes32 => bytes32)) public currentRound;
    mapping(bytes32 => mapping(bytes32 => Status)) private storedStatus;
    mapping(bytes32 => bool) public revoked;
    mapping(bytes32 => bytes32) public revokedRound;
    mapping(bytes32 => bool) public revokedBytes;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => uint64) public quarantinedAt;
    mapping(bytes32 => uint64) public quarantineUntil;
    mapping(bytes32 => mapping(address => uint64)) public lastQuarantineAt;
    bytes32 private constant TYPEHASH = keccak256("Attestation(bytes32 releaseId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bytes32 policyHash,bytes32 evidenceHash,uint8 verdict,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion,uint256 nonce,uint256 deadline)");
    bytes32 private constant QUARANTINE_TYPEHASH = keccak256("Quarantine(bytes32 releaseId,bytes32 policyHash,bytes32 evidenceHash,bytes32 reasonCode,uint64 expiresAt,uint32 validatorSetVersion,uint256 nonce,uint256 deadline)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 public constant CANARY_EXFILTRATION = keccak256("CANARY_EXFILTRATION");
    bytes32 public constant HOST_ESCAPE_ATTEMPT = keccak256("HOST_ESCAPE_ATTEMPT");
    bytes32 public constant DIGEST_MISMATCH = keccak256("DIGEST_MISMATCH");
    event ReleaseRegistered(bytes32 indexed releaseId, bytes32 indexed toolId, bytes32 artifactDigest, bytes32 manifestDigest, bytes32 toolSurfaceDigest);
    event RoundOpened(bytes32 indexed roundId, bytes32 indexed releaseId, bytes32 indexed policyHash, uint64 validFrom, uint64 validUntil, uint32 validatorSetVersion);
    event VoteRecorded(bytes32 indexed roundId, bytes32 indexed releaseId, address indexed validator, uint8 verdict, bytes32 evidenceHash, bool afterDecision);
    event RoundDecided(bytes32 indexed roundId, bytes32 indexed releaseId, bytes32 indexed policyHash, Outcome outcome, uint8 approvals, uint8 rejections, uint8 abstentions);
    event ReviewRequired(bytes32 indexed releaseId, bytes32 indexed policyHash, bytes32 indexed roundId);
    event ReleaseRevoked(bytes32 indexed releaseId, bytes32 indexed policyHash, bytes32 indexed roundId);
    /// Every releaseId with these bytes now reads REVOKED, including twins registered earlier.
    event BytesRevoked(bytes32 indexed bytesKey, bytes32 artifactDigest, bytes32 manifestDigest, bytes32 toolSurfaceDigest, bytes32 indexed roundId);
    event ReleaseQuarantined(bytes32 indexed releaseId, address indexed validator, bytes32 indexed policyHash, bytes32 reasonCode, bytes32 evidenceHash, uint64 expiresAt);
    event ReleaseStatusChanged(bytes32 indexed releaseId, bytes32 indexed policyHash, Status previousStatus, Status newStatus, bytes32 reasonCode, bytes32 evidenceRoot);
    constructor(address admin, ValidatorRegistry validatorRegistry, PolicyRegistry policyRegistry) {
        require(admin != address(0) && address(validatorRegistry) != address(0) && address(policyRegistry) != address(0), "INVALID_CONFIG");
        owner = admin; validators = validatorRegistry; policies = policyRegistry;
    }
    function registerRelease(bytes32 toolId, bytes32 artifact, bytes32 manifest, bytes32 surface) external returns (bytes32 key) {
        require(msg.sender == owner, "ONLY_OWNER");
        require(toolId != bytes32(0) && artifact != bytes32(0) && manifest != bytes32(0) && surface != bytes32(0), "EMPTY_HASH");
        // Revocation binds the bytes, so a revoked build cannot come back under a new tool id.
        require(!revokedBytes[_bytesKey(artifact, manifest, surface)], "REVOKED_BYTES");
        key = keccak256(abi.encode(toolId, artifact, manifest, surface));
        require(!releases[key].exists, "ALREADY_REGISTERED");
        releases[key] = Identity(toolId, artifact, manifest, surface, true);
        emit ReleaseRegistered(key, toolId, artifact, manifest, surface);
    }
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("MCPShieldReleaseRegistry"), keccak256("3"), block.chainid, address(this)));
    }
    function attestationDigest(Attestation calldata a) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(TYPEHASH, a))));
    }
    function roundIdOf(bytes32 releaseId, bytes32 policyHash, uint64 validFrom, uint64 validUntil, uint32 validatorSetVersion) public pure returns (bytes32) {
        return keccak256(abi.encode(releaseId, policyHash, validFrom, validUntil, validatorSetVersion));
    }
    function submitAttestation(Attestation calldata a, bytes calldata signature) external {
        Identity memory identity = releases[a.releaseId];
        require(identity.exists && identity.artifactDigest == a.artifactDigest && identity.manifestDigest == a.manifestDigest
            && identity.toolSurfaceDigest == a.toolSurfaceDigest, "IDENTITY_MISMATCH");
        require(block.timestamp <= a.deadline && a.validFrom <= block.timestamp && a.validUntil > block.timestamp
            && a.validUntil > a.validFrom && a.validUntil <= a.validFrom + 30 days, "EXPIRED_OR_INVALID_VALIDITY");
        require(policies.active(a.policyHash), "INACTIVE_POLICY");
        require(a.evidenceHash != bytes32(0) && a.verdict <= uint8(Verdict.ABSTAIN), "INVALID_VERDICT");
        require(a.validatorSetVersion == validators.version(), "STALE_VALIDATOR_SET");
        address signer = _recover(attestationDigest(a), signature);
        require(validators.isActiveValidator(signer, a.validatorSetVersion), "NOT_VALIDATOR");
        require(a.nonce == nonces[signer], "REPLAY");
        bytes32 roundId = roundIdOf(a.releaseId, a.policyHash, a.validFrom, a.validUntil, a.validatorSetVersion);
        Round storage round = rounds[roundId];
        // After revocation only the revoking round still takes votes, so late dissent is kept.
        require(!_revokedIdentity(a.releaseId, identity) || round.outcome == Outcome.REJECTED, "TERMINAL_RELEASE");
        require(!votes[roundId][signer].cast, "DUPLICATE_VOTE");
        if (round.validUntil == 0) {
            round.releaseId = a.releaseId; round.policyHash = a.policyHash; round.validFrom = a.validFrom;
            round.validUntil = a.validUntil; round.validatorSetVersion = a.validatorSetVersion; round.openedAt = uint64(block.timestamp);
            emit RoundOpened(roundId, a.releaseId, a.policyHash, a.validFrom, a.validUntil, a.validatorSetVersion);
        }
        nonces[signer] = a.nonce + 1;
        votes[roundId][signer] = Vote(true, a.verdict, a.evidenceHash);
        if (a.verdict == uint8(Verdict.PASS)) ++round.approvals;
        else if (a.verdict == uint8(Verdict.FAIL)) ++round.rejections;
        else ++round.abstentions;
        bool afterDecision = round.outcome != Outcome.OPEN;
        emit VoteRecorded(roundId, a.releaseId, signer, a.verdict, a.evidenceHash, afterDecision);
        if (!afterDecision) _settle(roundId, round, identity);
    }
    function _settle(bytes32 roundId, Round storage round, Identity memory identity) private {
        if (round.rejections >= 2) round.outcome = Outcome.REJECTED;
        else if (round.approvals >= 2) round.outcome = Outcome.APPROVED;
        else if (uint256(round.approvals) + round.rejections + round.abstentions >= 3) round.outcome = Outcome.SPLIT;
        else return;
        round.decidedAt = uint64(block.timestamp);
        emit RoundDecided(roundId, round.releaseId, round.policyHash, round.outcome, round.approvals, round.rejections, round.abstentions);
        if (round.outcome == Outcome.REJECTED) {
            revoked[round.releaseId] = true; revokedRound[round.releaseId] = roundId;
            bytes32 bytesKey = _bytesKey(identity.artifactDigest, identity.manifestDigest, identity.toolSurfaceDigest);
            revokedBytes[bytesKey] = true;
            emit ReleaseRevoked(round.releaseId, round.policyHash, roundId);
            emit BytesRevoked(bytesKey, identity.artifactDigest, identity.manifestDigest, identity.toolSurfaceDigest, roundId);
            _transition(round.releaseId, round.policyHash, Status.REVOKED, keccak256("FAIL_QUORUM"), roundId);
            return;
        }
        // A newer scan replaces the live decision; an older round that finishes late only stays on record.
        // Newer = later validFrom, or the same validFrom and opened later (a retry of a stuck round).
        bytes32 live = currentRound[round.releaseId][round.policyHash];
        if (live != bytes32(0) && (round.validFrom < rounds[live].validFrom
            || (round.validFrom == rounds[live].validFrom && round.openedAt <= rounds[live].openedAt))) return;
        currentRound[round.releaseId][round.policyHash] = roundId;
        Status next = getDecision(round.releaseId, round.policyHash).status;
        bytes32 reason;
        if (round.outcome == Outcome.SPLIT) {
            reason = keccak256("SPLIT_VOTE");
            emit ReviewRequired(round.releaseId, round.policyHash, roundId);
        } else {
            // An approval of a scan taken before the last quarantine is recorded but does not verify.
            reason = next == Status.VERIFIED || next == Status.QUARANTINED ? keccak256("PASS_QUORUM") : keccak256("STALE_APPROVAL");
        }
        _transition(round.releaseId, round.policyHash, next, reason, roundId);
    }
    function quarantine(bytes32 releaseId, bytes32 policyHash, bytes32 evidenceHash, bytes32 reasonCode, uint64 expiresAt) external {
        require(validators.isActiveValidator(msg.sender, validators.version()), "NOT_VALIDATOR");
        _quarantine(msg.sender, releaseId, policyHash, evidenceHash, reasonCode, expiresAt);
    }
    function quarantineBySignature(Quarantine calldata q, bytes calldata signature) external {
        require(block.timestamp <= q.deadline, "SIGNATURE_EXPIRED");
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(QUARANTINE_TYPEHASH, q))));
        address signer = _recover(digest, signature);
        require(validators.isActiveValidator(signer, q.validatorSetVersion), "NOT_VALIDATOR");
        require(nonces[signer] == q.nonce, "REPLAY");
        nonces[signer] = q.nonce + 1;
        _quarantine(signer, q.releaseId, q.policyHash, q.evidenceHash, q.reasonCode, q.expiresAt);
    }
    function _quarantine(address validator, bytes32 releaseId, bytes32 policyHash, bytes32 evidenceHash, bytes32 reasonCode, uint64 expiresAt) private {
        require(releases[releaseId].exists && !_revokedIdentity(releaseId, releases[releaseId]), "INVALID_RELEASE");
        require(policies.active(policyHash) && evidenceHash != bytes32(0), "INVALID_EVIDENCE");
        require(reasonCode == CANARY_EXFILTRATION || reasonCode == HOST_ESCAPE_ATTEMPT || reasonCode == DIGEST_MISMATCH, "NON_DETERMINISTIC_REASON");
        require(expiresAt > block.timestamp && expiresAt <= block.timestamp + 1 days, "INVALID_TTL");
        require(quarantineUntil[releaseId] <= block.timestamp, "ALREADY_QUARANTINED");
        // One emergency brake per validator per release. A release is fixed bytes, so later findings go
        // through FAIL votes; otherwise one validator could re-quarantine after every honest re-scan.
        require(lastQuarantineAt[releaseId][validator] == 0, "QUARANTINE_USED");
        lastQuarantineAt[releaseId][validator] = uint64(block.timestamp);
        quarantinedAt[releaseId] = uint64(block.timestamp); quarantineUntil[releaseId] = expiresAt;
        emit ReleaseQuarantined(releaseId, validator, policyHash, reasonCode, evidenceHash, expiresAt);
        // A fresh quarantine is always an event, even over a stale stored QUARANTINED.
        Status previousStatus = storedStatus[releaseId][policyHash];
        storedStatus[releaseId][policyHash] = Status.QUARANTINED;
        emit ReleaseStatusChanged(releaseId, policyHash, previousStatus, Status.QUARANTINED, reasonCode, evidenceHash);
    }
    function getDecision(bytes32 releaseId, bytes32 policyHash) public view returns (Decision memory d) {
        Identity memory identity = releases[releaseId];
        require(identity.exists, "UNKNOWN_RELEASE");
        bytes32 live = currentRound[releaseId][policyHash];
        if (revoked[releaseId] && revokedRound[releaseId] != bytes32(0)) live = revokedRound[releaseId];
        Round memory round = rounds[live];
        d = Decision(live, round.validFrom, round.validUntil, quarantineUntil[releaseId], round.validatorSetVersion,
            round.approvals, round.rejections, Status.UNVERIFIED);
        if (_revokedIdentity(releaseId, identity)) d.status = Status.REVOKED;
        else if (quarantineUntil[releaseId] > block.timestamp) d.status = Status.QUARANTINED;
        else if (live == bytes32(0)) d.status = quarantinedAt[releaseId] == 0 ? Status.UNVERIFIED : Status.EXPIRED;
        else if (round.outcome == Outcome.SPLIT) d.status = Status.UNVERIFIED;
        else if (round.validFrom <= block.timestamp && round.validUntil > block.timestamp
            && round.validatorSetVersion == validators.version() && policies.active(policyHash)
            && (quarantinedAt[releaseId] == 0 || round.validFrom > quarantinedAt[releaseId])) d.status = Status.VERIFIED;
        else d.status = Status.EXPIRED;
    }
    function getRound(bytes32 roundId) external view returns (Round memory) { return rounds[roundId]; }
    function getVote(bytes32 roundId, address validator) external view returns (Vote memory) { return votes[roundId][validator]; }
    function needsReview(bytes32 releaseId, bytes32 policyHash) external view returns (bool) {
        bytes32 live = currentRound[releaseId][policyHash];
        return live != bytes32(0) && rounds[live].outcome == Outcome.SPLIT && getDecision(releaseId, policyHash).status == Status.UNVERIFIED;
    }
    function syncExpiry(bytes32 releaseId, bytes32 policyHash) external {
        Decision memory effective = getDecision(releaseId, policyHash);
        Status stored = storedStatus[releaseId][policyHash];
        bytes32 reason = effective.status == Status.REVOKED ? keccak256("REVOKED")
            : stored == Status.QUARANTINED && effective.status == Status.VERIFIED ? keccak256("QUARANTINE_ENDED") : keccak256("EXPIRY");
        _transition(releaseId, policyHash, effective.status, reason, effective.reportRoot);
    }
    function _transition(bytes32 releaseId, bytes32 policyHash, Status next, bytes32 reason, bytes32 evidenceRoot) private {
        Status previous = storedStatus[releaseId][policyHash];
        if (previous == next) return;
        storedStatus[releaseId][policyHash] = next;
        emit ReleaseStatusChanged(releaseId, policyHash, previous, next, reason, evidenceRoot);
    }
    function _revokedIdentity(bytes32 releaseId, Identity memory identity) private view returns (bool) {
        return revoked[releaseId] || revokedBytes[_bytesKey(identity.artifactDigest, identity.manifestDigest, identity.toolSurfaceDigest)];
    }
    function _bytesKey(bytes32 artifact, bytes32 manifest, bytes32 surface) private pure returns (bytes32) {
        return keccak256(abi.encode(artifact, manifest, surface));
    }
    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        require(signature.length == 65, "INVALID_SIGNATURE");
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
        require(uint256(s) <= HALF_N && (v == 27 || v == 28), "INVALID_SIGNATURE");
        signer = ecrecover(digest, v, r, s); require(signer != address(0), "INVALID_SIGNATURE");
    }
}
