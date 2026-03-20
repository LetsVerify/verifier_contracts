// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BN254} from "./lib.sol";

contract Verifier {
    using BN254 for BN254.G1Point;

    BN254.G1Point internal g1;
    BN254.G2Point internal g2;

    uint256 public constant FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    address public owner;

    /// @notice BBS+ signature: (A, e, s)
    struct Signature {
        BN254.G1Point A;
        uint256 e;
        uint256 s;
    }

    /// @notice Public parameters
    /// H[0] = h0, H[1..L] for messages
    struct Parameters {
        uint256 L;
        BN254.G1Point[] H;
    }

    /// @notice Public key: w = x*g2
    struct PublicKey {
        BN254.G2Point w;
    }

    Parameters internal params;
    PublicKey internal pk;

    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    event PublicKeyUpdated(uint256[2] x, uint256[2] y);
    event ParametersUpdated(uint256 L);
    event GeneratorsUpdated();

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(Parameters memory _params, PublicKey memory _pk) {
        require(_params.H.length == _params.L + 1, "H length must be L+1");

        owner = msg.sender;

        g1 = BN254.g1Generator();
        g2 = BN254.g2Generator();

        _setParameters(_params);
        _setPublicKey(_pk);
    }

    // -------------------------
    // Owner admin
    // -------------------------

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        address old = owner;
        owner = newOwner;
        emit OwnerUpdated(old, newOwner);
    }

    function updatePublicKey(PublicKey memory _pk) external onlyOwner {
        _setPublicKey(_pk);
    }

    function updateParameters(Parameters memory _params) external onlyOwner {
        require(_params.H.length == _params.L + 1, "H length must be L+1");
        _setParameters(_params);
    }

    /// @notice allows updating generators
    function updateGenerators(BN254.G1Point memory _g1, BN254.G2Point memory _g2) external onlyOwner {
        g1 = _g1;
        g2 = _g2;
        emit GeneratorsUpdated();
    }

    function _setPublicKey(PublicKey memory _pk) internal {
        pk = _pk;
        emit PublicKeyUpdated(_pk.w.x, _pk.w.y);
    }

    function _setParameters(Parameters memory _params) internal {
        delete params.H;
        params.L = _params.L;

        for (uint256 i = 0; i < _params.H.length; i++) {
            params.H.push(_params.H[i]);
        }

        emit ParametersUpdated(_params.L);
    }

    // -------------------------
    // Views
    // -------------------------

    function getPublicKey() external view returns (PublicKey memory) {
        return pk;
    }

    function getGenerators() external view returns (BN254.G1Point memory, BN254.G2Point memory) {
        return (g1, g2);
    }

    function getParametersMeta() external view returns (uint256 L, uint256 hLen) {
        return (params.L, params.H.length);
    }

    function getH(uint256 i) external view returns (BN254.G1Point memory) {
        require(i < params.H.length, "index oob");
        return params.H[i];
    }

    // -------------------------
    // BBS+ verify
    // e(A, w + e*g2) == e(g1 + h0*s + sum(h_i*m_i), g2)
    // -------------------------
    function verify(Signature memory sig, uint256[] memory messages) external view returns (bool) {
        BN254.G1Point[] storage H = params.H;
        uint256 L = params.L;
        require(messages.length == L, "invalid message length");
        require(sig.e < FR_MODULUS && sig.s < FR_MODULUS, "scalar out of field");

        BN254.G1Point memory B = g1.plus(H[0].scalarMul(sig.s));

        for (uint256 i = 0; i < messages.length;) {
            B = B.plus(H[i + 1].scalarMul(messages[i] % FR_MODULUS));
            unchecked {
                ++i;
            }
        }

        BN254.G1Point memory eA = sig.A.scalarMul(sig.e);
        BN254.G1Point memory negB = BN254.negate(B);

        return BN254.pairing3(sig.A, pk.w, eA, g2, negB, g2);
    }
}
