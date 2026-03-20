// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/verifier.sol";
import "../src/lib.sol";

contract VerifierTest is Test {
    Verifier internal verifier;

    address internal owner = address(this);
    address internal alice = address(0xA11CE);

    function setUp() public {
        BN254.G1Point[] memory H = new BN254.G1Point[](6);
        H[0] = BN254.G1Point({
            x: 1240703902419481545648986623473745806820787811594483762868555478458184666010,
            y: 18256809644617940920254137422873442228473372063501986223346572230462785524439
        });
        H[1] = BN254.G1Point({
            x: 13020051060923754131228834502880722230806022247808159414293488215070332394772,
            y: 4529195280833079968741232889459250032235684423945803123503195484318934791269
        });
        H[2] = BN254.G1Point({
            x: 16297305326858617051978407466566022015897499588105011865519416711980789611480,
            y: 3457763090096090198366700259693644531770479248862060079356697617968728920669
        });
        H[3] = BN254.G1Point({
            x: 2253800715866524994843494300154676387161899760404330152495442103191129641090,
            y: 9799921154527725974487574934896288658143635125210110869057393462183450014056
        });
        H[4] = BN254.G1Point({
            x: 15591676955350207499762345130216057388364340524562767442403038585836757427173,
            y: 366693626097570863962860699973119751999356879228643136313636147692477681999
        });
        H[5] = BN254.G1Point({
            x: 21393812497764701958592826102470503271515498520329721604743009071119726253411,
            y: 16563212233814295780128168415970014578295470256244992910750946401593357383812
        });

        Verifier.Parameters memory p = Verifier.Parameters({L: 5, H: H});

        Verifier.PublicKey memory pk = Verifier.PublicKey({
            w: BN254.G2Point({
                x: [
                    uint256(2232839732669254255570633474824418750160328472838894459159066665737716854793),
                    uint256(1638476717045483828051788814817931651347605310925436796672129679185498513100)
                ],
                y: [
                    uint256(7317755297609798625734717923286665529707296035764165867718474063260595021529),
                    uint256(4673185690031462075916309452952039391878276267113987098257105814684493193332)
                ]
            })
        });

        verifier = new Verifier(p, pk);
    }

    function testOwnerIsDeployer() public view {
        assertEq(verifier.owner(), owner);
    }

    function testOnlyOwnerCanUpdatePublicKey() public {
        Verifier.PublicKey memory newPk = Verifier.PublicKey({
            w: BN254.G2Point({
                x: [
                    uint256(2232839732669254255570633474824418750160328472838894459159066665737716854793),
                    uint256(1638476717045483828051788814817931651347605310925436796672129679185498513100)
                ],
                y: [
                    uint256(7317755297609798625734717923286665529707296035764165867718474063260595021529),
                    uint256(4673185690031462075916309452952039391878276267113987098257105814684493193332)
                ]
            })
        });

        vm.prank(alice);
        vm.expectRevert("not owner");
        verifier.updatePublicKey(newPk);

        verifier.updatePublicKey(newPk);
    }

    function testParamsLoadedFromPreset() public view {
        (uint256 L, uint256 hLen) = verifier.getParametersMeta();
        assertEq(L, 5);
        assertEq(hLen, 6);

        BN254.G1Point memory h0 = verifier.getH(0);
        assertEq(h0.x, 1240703902419481545648986623473745806820787811594483762868555478458184666010);
    }

    function testStaticSignature() public view {
        Verifier.Signature memory sig = Verifier.Signature({
            A: BN254.G1Point({
                x: 15420961703146650397185562128389287319053429998638815663511846943900939302280,
                y: 10599458432123703481590215785551611417694452230685267431202332057041540300547
            }),
            e: 1328790040692576325258580129229001772890358018148159309458854770206210226319,
            s: 5880579452694111398038816184147859226105113334752339841727721355533812240766
        });

        uint256[] memory msgs = new uint256[](5);
        msgs[0] = 1;
        msgs[1] = 2;
        msgs[2] = 3;
        msgs[3] = 4;
        msgs[4] = 5;

        bool ok = verifier.verify(sig, msgs);
        ok;
    }
}
