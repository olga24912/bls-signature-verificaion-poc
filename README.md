# Proof of Concept: using BLS12-381 host-functions for BLS signature verification

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