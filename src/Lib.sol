// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BN254 math helpers for on-chain verifiers (alt_bn128 precompiles)
/// @notice Provides G1/G2 structs and wrappers around ECADD/ECMUL/PAIRING precompiles.
library BN254 {
    // use for Scalars
    uint256 internal constant FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // use for Fq (G1/G2)
    uint256 internal constant FQ_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    // Fp2 element represented as a + bi => [a, b]
    // Ethereum precompile expects specific ordering in calldata; keep helper methods consistent.
    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    /// @dev Generator of G1
    function g1Generator() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// @dev Generator of G2 (Ethereum alt_bn128 standard generator)
    function g2Generator() internal pure returns (G2Point memory) {
        return G2Point(
            [
                uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
                uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634)
            ],
            [
                uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
                uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531)
            ]
        );
    }

    function isInfinity(G1Point memory p) internal pure returns (bool) {
        return p.x == 0 && p.y == 0;
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (isInfinity(p)) return G1Point(0, 0);
        // y = -y mod q
        return G1Point(p.x, FQ_MODULUS - (p.y % FQ_MODULUS));
    }

    /// @dev Calls precompile 0x06 (bn256Add) - no temp array
    function plus(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        bool success;
        assembly {
            let ptr := mload(0x40)

            mstore(ptr, mload(p1)) // p1.x
            mstore(add(ptr, 0x20), mload(add(p1, 0x20))) // p1.y
            mstore(add(ptr, 0x40), mload(p2)) // p2.x
            mstore(add(ptr, 0x60), mload(add(p2, 0x20))) // p2.y

            success := staticcall(gas(), 0x06, ptr, 0x80, r, 0x40)
        }
        require(success, "BN254: ecadd failed");
    }

    /// @dev Calls precompile 0x07 (bn256ScalarMul) - no temp array
    function scalarMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        bool success;
        assembly {
            let ptr := mload(0x40)

            mstore(ptr, mload(p)) // p.x
            mstore(add(ptr, 0x20), mload(add(p, 0x20))) // p.y
            mstore(add(ptr, 0x40), s) // scalar

            success := staticcall(gas(), 0x07, ptr, 0x60, r, 0x40)
        }
        require(success, "BN254: ecmul failed");
    }

    /// @dev Pairing check using precompile 0x08
    /// e(p1[0], p2[0]) * ... * e(p1[n], p2[n]) == 1
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length, "BN254: length mismatch");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < elements; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].x;
            input[j + 1] = p1[i].y;

            input[j + 2] = p2[i].x[1];
            input[j + 3] = p2[i].x[0];
            input[j + 4] = p2[i].y[1];
            input[j + 5] = p2[i].y[0];
        }

        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(gas(), 0x08, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }
        require(success, "BN254: pairing failed");
        return out[0] == 1;
    }

    /// @dev Convenience: pairing for 2 pairs
    function pairing2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2)
        internal
        view
        returns (bool)
    {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    function pairing3(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        uint256[18] memory input = [
            a1.x,
            a1.y,
            a2.x[1],
            a2.x[0],
            a2.y[1],
            a2.y[0],
            b1.x,
            b1.y,
            b2.x[1],
            b2.x[0],
            b2.y[1],
            b2.y[0],
            c1.x,
            c1.y,
            c2.x[1],
            c2.x[0],
            c2.y[1],
            c2.y[0]
        ];

        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(gas(), 0x08, input, 0x240, out, 0x20)
        }
        require(success, "BN254: pairing failed");
        return out[0] == 1;
    }

    /// @dev Convenience: pairing for 4 pairs
    function pairing4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);

        p1[0] = a1;
        p2[0] = a2;
        p1[1] = b1;
        p2[1] = b2;
        p1[2] = c1;
        p2[2] = c2;
        p1[3] = d1;
        p2[3] = d2;

        return pairing(p1, p2);
    }
}
