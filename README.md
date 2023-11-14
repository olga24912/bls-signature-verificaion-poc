# Proof of Concept: using BLS12-381 host-functions for BLS signature verification

The contract in this repository shows how to implement BLS-signatures verification by using 
the host functions proposed in the https://github.com/near/NEPs/pull/488

For testing, we use the real data from Ethereum Light Client Updates.

The host-functions implementation: https://github.com/near/nearcore/pull/9317

## Running tests
For running tests 
1. clone nearcore repo and switch branch
```shell
git clone https://github.com/aurora-is-near/nearcore.git
cd nearcore
git checkout bls12-381
```

2. compile nearcore (from nearcore folder)
```shell
make sandbox
```

3. setup env variable
```shell
export NEAR_SANDBOX_BIN_PATH=<PATH_TO_NEARCORE_FOLDEER>/target/debug/near-sandbox
```

4. compile the contract (from this folder)
```shell
./build.sh
```

5. run tests
```shell
cargo test -- --show-output
```

## Gas consumption
Estimated gas consumption: ~16 TGas

The current implementation is tested on the data from the Ethereum Light Client Update. Gas is estimated inside the sandbox.
Gas prices for the host functions can be inaccurate and can change in the future. Important moment: hashing message into fp2
is cheap(~2 TGas).