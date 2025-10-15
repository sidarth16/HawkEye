// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/*
  VulnerableMerkleTest.sol

  A flat test contract that intentionally demonstrates multiple insecure patterns
  for updating merkle roots. Use this to validate static detectors:
    - missing access control
    - weak checks (tx.origin)
    - misconfigured role system (publicly grantable)
    - indirect update via delegatecall / proxy pattern
    - multiple roots / phase changes with inconsistent controls
*/

contract VulnerableMerkleTest {
    // --- storage ---
    bytes32 public merkleRoot;            // MAIN root (can be changed in many ways)
    bytes32 public whitelistRoot;        // SECONDARY root (different protection)
    bytes32 public phaseRoot;            // PHASE root (versioned)
    address public owner;                // naive owner
    address public implementation;       // proxy-like implementation

    // Misconfigured role system: anyone can grant this role (vulnerable)
    mapping(address => bool) public adminRole;

    // naive claimed mapping per root-phase (not the focus, but present)
    mapping(bytes32 => mapping(address => bool)) public claimed;

    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, address indexed by);
    event WhitelistRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, address indexed by);
    event PhaseRootUpdated(uint256 phase, bytes32 indexed oldRoot, bytes32 indexed newRoot, address indexed by);
    event ImplementationUpdated(address indexed oldImpl, address indexed newImpl, address indexed by);

    constructor(bytes32 _initialRoot) {
        owner = msg.sender;
        merkleRoot = _initialRoot; // initial root set in constructor (ok-ish)
    }

    // ---------------------------
    // 1) UNPROTECTED UPDATE (HIGH RISK)
    // ---------------------------
    // Anyone can call this and replace the global merkleRoot.
    // Detector target: direct assignment to merkleRoot in an external function without access control.
    function updateRoot_unprotected(bytes32 _newRoot) external {
        bytes32 old = merkleRoot;
        merkleRoot = _newRoot; // <-- vulnerable write
        emit MerkleRootUpdated(old, _newRoot, msg.sender);
    }

    // ---------------------------
    // 2) WEAK CHECK USING tx.origin (MEDIUM-HIGH RISK)
    // ---------------------------
    // Uses tx.origin for auth (discouraged; susceptible to phishing via intermediary contracts).
    function updateRoot_txorigin(bytes32 _newRoot) external {
        require(tx.origin == owner, "Not owner via tx.origin"); // weak guard
        bytes32 old = merkleRoot;
        merkleRoot = _newRoot; // <-- vulnerable (weak protection)
        emit MerkleRootUpdated(old, _newRoot, tx.origin);
    }

    // ---------------------------
    // 3) ROLE-BASED BUT MISCONFIGURED (MEDIUM-HIGH RISK)
    // ---------------------------
    // adminRole can be granted by anyone (grantAdmin is public). Grants effectively meaningless.
    function grantAdmin(address who) external {
        // No access control — anybody can call grantAdmin
        adminRole[who] = true; // <-- vulnerability in role management
    }

    function revokeAdmin(address who) external {
        // Also no control over revocation
        adminRole[who] = false;
    }

    // This function uses the role, but because roles are grantable by any caller,
    // it offers no real protection.
    function updateWhitelist_root_by_role(bytes32 _newRoot) external {
        require(adminRole[msg.sender], "Not adminRole");
        bytes32 old = whitelistRoot;
        whitelistRoot = _newRoot; // <-- protected by misconfigured role
        emit WhitelistRootUpdated(old, _newRoot, msg.sender);
    }

    // ---------------------------
    // 4) VERSIONED/PHASED ROOT (INCONSISTENT CONTROLS)
    // ---------------------------
    // Demonstrates multiple roots and switching phase roots; inconsistent controls across functions.
    mapping(uint256 => bytes32) public phaseRoots;
    uint256 public activePhase;

    // Only owner can set the activePhase — but owner might be weakly protected elsewhere.
    function setActivePhase(uint256 p) external {
        require(msg.sender == owner, "Only owner can set phase");
        activePhase = p;
    }

    // Phase root update is publicly callable (no checks) — inconsistent policy with setActivePhase.
    function setPhaseRoot_public(uint256 phase, bytes32 newRoot) external {
        bytes32 old = phaseRoots[phase];
        phaseRoots[phase] = newRoot; // <-- vulnerable write; no checks
        emit PhaseRootUpdated(phase, old, newRoot, msg.sender);
    }


    function update(bytes32 _newRoot) external {
        bytes32 old = merkleRoot;
        merkleRoot = _newRoot; 
        emit MerkleRootUpdated(old, _newRoot, msg.sender);
    }

     function setPhaseRoot_blacklisdt(uint256 phase, bytes32 newRoot) external {
        require(msg.sender != owner, "only owner");
        bytes32 old = phaseRoots[phase];
        phaseRoots[phase] = newRoot; // <-- protected version
        emit PhaseRootUpdated(phase, old, newRoot, msg.sender);
    }

    // A different function doing the same update but protected by owner (inconsistent).
    function setPhaseRoot_owner(uint256 phase, bytes32 newRoot) external {
        require(msg.sender == owner, "only owner");
        bytes32 old = phaseRoots[phase];
        phaseRoots[phase] = newRoot; // <-- protected version
        emit PhaseRootUpdated(phase, old, newRoot, msg.sender);
    }

    // ---------------------------
    // 5) PROXY / DELEGATECALL PATH (CRITICAL)
    // ---------------------------
    // An implementation address can be set by anyone (no control), and the contract allows
    // arbitrary delegatecall to that implementation. If the implementation writes to the
    // storage slot that holds merkleRoot, it can overwrite it indirectly.
    //
    // This models the dangerous pattern: "proxy upgrade or delegatecall without access control".
    function setImplementation_unprotected(address impl) external {
        address old = implementation;
        implementation = impl; // <-- unprotected implementation update
        emit ImplementationUpdated(old, impl, msg.sender);
    }

    // Arbitrary delegatecall to implementation (no access control)
    function exec_delegatecall(bytes calldata data) external returns (bool success, bytes memory ret) {
        // delegatecall into implementation with caller control over data
        (success, ret) = implementation.delegatecall(data); // <-- critical: can mutate this contract's storage
        require(success, "delegatecall failed");
    }

    // Helper: allows an attacker to have the contract execute arbitrary code via delegatecall
    // which could update merkleRoot at storage slot.
    // Note: the implementation contract’s code could contain a function which writes to storage slot
    // corresponding to merkleRoot — thus indirect root update.
    //
    // Detector target: delegatecall usage plus writable merkleRoot storage slot.

    // ---------------------------
    // 6) INDIRECT WRITE VIA CALL TO ANOTHER CONTRACT (UNGUARDED)
    // ---------------------------
    // Call an external contract that may call back or modify state using an unprotected interface.
    function callExternalAndTrust(address target, bytes calldata data) external {
        // No checks on the target — may call into a malicious contract
        (bool ok, ) = target.call(data);
        require(ok, "external call failed");
    }

    // ---------------------------
    // 7) MERKLE CLAIM (uses merkleRoot)
    // ---------------------------
    // A simple example claim function that validates against the current merkleRoot.
    // If merkleRoot is changed by any of the above methods, proofs may be invalidated or attacker-crafted.
    function claim(bytes32[] calldata proof, uint256 amount, address account) external {
        require(!claimed[merkleRoot][account], "Already claimed for this root");
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        require(_verifyMerkle(proof, merkleRoot, leaf), "Bad proof"); // respects current merkleRoot
        claimed[merkleRoot][account] = true;
        // token transfer / mint logic would go here in a real contract
    }

    // Simple (naive) Merkle verify — iterative hashing (not optimized)
    function _verifyMerkle(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (computed <= p) {
                computed = keccak256(abi.encodePacked(computed, p));
            } else {
                computed = keccak256(abi.encodePacked(p, computed));
            }
        }
        return computed == root;
    }

    // ---------------------------
    // 8) ADMIN-ONLY (GOOD) EXAMPLE FOR COMPARISON
    // ---------------------------
    // This is a correctly-protected update for testers to compare against.
    // In tests, detectors should *not* flag this as vulnerable.
    function updateRoot_ownerOnly(bytes32 _newRoot) external {
        require(msg.sender == owner, "only owner");
        bytes32 old = merkleRoot;
        merkleRoot = _newRoot; // <-- properly protected by owner check
        emit MerkleRootUpdated(old, _newRoot, msg.sender);
    }

    // A helper to transfer ownership (unprotected transferRecipientApproved would be bad; here we require owner)
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "only owner");
        owner = newOwner;
    }
}
