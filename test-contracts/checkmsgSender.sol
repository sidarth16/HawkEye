// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

    function updateRoot(bytes32 _newRoot) public {
        require(msg.sender == owner, "only owner");
        bytes32 old = merkleRoot;
        merkleRoot = _newRoot; // <-- properly protected by owner check
        emit MerkleRootUpdated(old, _newRoot, msg.sender);
    }


    // function getMsgSenderWrapper() internal view returns(address){
    //     return getMsgSender();
    // }

    function getMsgSender() internal view returns(address){
        address a = msg.sender;
        address b = a;
        return b;
    }

    function checkCallerIsOwner() internal view returns(bool){
        return getMsgSender() == owner;
    }



    function updateRoot_1(bytes32 _newRoot) internal {
        // require(getMsgSender() == owner, "only owner");
        if (checkCallerIsOwner()){
            bytes32 old = merkleRoot;
            merkleRoot = _newRoot; // <-- properly protected by owner check
            emit MerkleRootUpdated(old, _newRoot, msg.sender);
        }
    }

    modifier onlyOwner() {
        require(checkCallerIsOwner(), 'owner only');
        _;
    }

    function updateRoot_2(bytes32 _newRoot) external onlyOwner() {
        updateRoot(_newRoot);
    }

    function updateRoot_3(bytes32 _newRoot) external {
        require(checkCallerIsOwner(), 'owner only');
        if (getMsgSender()==address(this)){
            return;
        }
        updateRoot_1(_newRoot);
    }


    // A helper to transfer ownership (unprotected transferRecipientApproved would be bad; here we require owner)
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "only owner");
        owner = newOwner;
    }
}
