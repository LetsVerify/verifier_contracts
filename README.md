# Intro

bbs on-chain verifier contracts

## How to use

1. Edit `.env` 
2. Run command below:
```bash
forge script script/DeployVerifier.s.sol:DeployVerifier \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast
```
3. To verify, use the command below:
```bash
cast call $VERIFIER_ADDRESS \
  "verify(((uint256,uint256),uint256,uint256),uint256[])(bool)" \
  "((Ax,Ay),e,s)" \
  "[M1,M2,M3]" \
  --rpc-url $RPC_URL
```

## Thanks

+ The precompile pairing references [zkREPL](https://zkrepl.dev/)