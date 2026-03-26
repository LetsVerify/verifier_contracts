// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/Verifier.sol";

contract DeployVerifier is Script {
    function run() external {
        // Read data
        string memory paramsJson = vm.envString("PARAMS_JSON");
        string memory pkJson = vm.envString("PK_JSON");

        // Deserialize
        uint256 L = vm.parseJsonUint(paramsJson, ".L");
        bytes memory hRaw = vm.parseJson(paramsJson, ".H");
        BN254.G1Point[] memory H = abi.decode(hRaw, (BN254.G1Point[]));

        Verifier.Parameters memory p;
        p.L = L;
        p.H = H;

        // Deserialize public key
        BN254.G2Point memory w;
        w.x[0] = vm.parseJsonUint(pkJson, ".w.x[0]");
        w.x[1] = vm.parseJsonUint(pkJson, ".w.x[1]");
        w.y[0] = vm.parseJsonUint(pkJson, ".w.y[0]");
        w.y[1] = vm.parseJsonUint(pkJson, ".w.y[1]");

        Verifier.PublicKey memory pk;
        pk.w = w;

        vm.startBroadcast();
        Verifier v = new Verifier(p, pk);
        vm.stopBroadcast();

        console2.log("Verifier deployed at:", address(v));
        console2.log("If you are using sepolia, see: https://sepolia.etherscan.io/address/", address(v));
    }
}