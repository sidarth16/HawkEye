// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title IVC Demo — vulnerable + safe example
/// @notice Educational demo for Input Validation Call detectors
contract IVCVulnerable {
    /// @notice Performs a delegatecall to a user-supplied target
    /// @dev Vulnerable: target is entirely user-controlled
    function delegateCallTo(address target, bytes calldata data) external returns (bytes memory) {
        // ATTENTION: using delegatecall to a user-supplied address is dangerous.
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    /// @notice Performs a low-level call to a user-supplied target
    /// @dev Vulnerable: no validation of `target`
    function lowLevelCallTo(address target, uint256 value, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    /// @notice Performs a staticcall to a user-supplied target
    /// @dev Vulnerable: staticcall to attacker-controlled contract can leak info if combined with other flaws
    function staticCallTo(address target, bytes calldata data) external view returns (bytes memory) {
        (bool ok, bytes memory ret) = target.staticcall(data);
        require(ok, "staticcall failed");
        return ret;
    }

    /// @notice Example of an "external call" wrapper that forwards gas/data
    /// @dev Vulnerable if `target` is derived from untrusted input and used for control flow
    function externalCallForward(address target, bytes calldata data) external returns (bytes memory) {
        // direct forward; no checks
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "forward failed");
        return ret;
    }

    // Allow the contract to receive ETH so lowLevelCallTo can forward value during testing
    receive() external payable {}


    // -----------------------------
    // Patterns that pass `target` through other functions
    // -----------------------------

    /// @notice Pass `target` to an internal helper which performs the delegatecall
    /// @dev Vulnerable: ownership/whitelist checks absent; delegation happens in helper
    function passToInternalDelegate(address target, bytes calldata data) external returns (bytes memory) {
        // passing `target` through to an internal helper
        return _internalDelegateHelper(target, data);
    }

    function _internalDelegateHelper(address _target, bytes calldata data) internal returns (bytes memory) {
        // actual delegatecall happens here — still vulnerable
        (bool ok, bytes memory ret) = _target.delegatecall(data);
        require(ok, "internal delegatecall failed");
        return ret;
    }


    // -----------------------------
    // Tainted-address examples using abi.decode
    // -----------------------------


    /// @notice Decode multiple values including an address, then forward call
    /// @dev Vulnerable: demonstrates more complex decoding (address, uint256, bytes)
    function taintedDecodeMultiple(bytes calldata encoded) external returns (bytes memory) {
        // expected format: abi.encode(address target, uint256 value, bytes payload)
        (address target, uint256 value, bytes memory payload) = abi.decode(encoded, (address, uint256, bytes));
        // direct use of decoded `target` is unsafe
        (bool ok, bytes memory ret) = target.call{value: value}(payload);
        require(ok, "taintedDecodeMultiple failed");
        return ret;
    }
}

/// @title IVC Safe Example
/// @notice Practical mitigations: owner-only whitelist for allowed targets
contract IVCSafe {
    address public owner;
    mapping(address => bool) public allowedTargets;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyAllowed(address target) {
        require(allowedTargets[target], "target not allowed");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Owner registers allowed call targets (trusted libraries/contracts)
    function addAllowedTarget(address target) external onlyOwner {
        allowedTargets[target] = true;
    }

    function removeAllowedTarget(address target) external onlyOwner {
        allowedTargets[target] = false;
    }

    // Safe delegatecall: only to whitelisted contracts
    function safeDelegateCallTo(address target, bytes calldata data)
        external
        onlyAllowed(target)
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    // Safe low-level call: only to whitelisted targets, optionally limit value forwarded
    function safeLowLevelCallTo(address target, uint256 value, bytes calldata data)
        external
        onlyAllowed(target)
        returns (bytes memory)
    {
        require(address(this).balance >= value, "insufficient balance");
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    // Safe staticcall: only to whitelisted targets
    function safeStaticCallTo(address target, bytes calldata data)
        external
        view
        onlyAllowed(target)
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.staticcall(data);
        require(ok, "staticcall failed");
        return ret;
    }

    // Simple ownership transfer for admin management
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero addr");
        owner = newOwner;
    }

    receive() external payable {}
}
