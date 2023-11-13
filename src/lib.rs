use near_sdk::near_bindgen;
use near_sdk::PanicOnDefault;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
struct BLSVerificationPOC {}

#[near_bindgen]
impl BLSVerificationPOC {
    #[init]
    pub fn new() -> Self { Self {} }

    //pub fn verify_bls_signature(&self, msg: Vec<u8>, signature: Vec<u8>, pubkeys: Vec<Vec<u8>>) -> bool {
    //    return true
    //}
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use tree_hash::TreeHash;
    use eth_types::eth2::{LightClientUpdate, SyncCommittee, PublicKeyBytes};
    use eth2_utility::consensus::compute_domain;
    use eth2_utility::consensus::DOMAIN_SYNC_COMMITTEE;
    use eth2_utility::consensus::compute_signing_root;
    use eth2_utility::consensus::{Network, NetworkConfig};
    use workspaces::{Account, Contract};
    use serde_json::json;
    use bitvec::order::Lsb0;
    use bitvec::prelude::BitVec;
    use std::str::FromStr;

    const WASM_FILEPATH: &str =
        "./target/wasm32-unknown-unknown/release/bls_verification_poc.wasm";

    #[macro_export]
    macro_rules! call {
        ($contract:ident, $method_name:literal) => {
            call_arg(&$contract, $method_name, &json!({}))
        };
        ($contract:ident, $method_name:literal, $args:expr) => {
            call_arg(&$contract, $method_name, $args)
        };
        ($account:expr, $contract:ident, $method_name:literal) => {
            call_by_with_arg($account, &$contract, $method_name, &json!({}))
        };
        ($account:expr, $contract:ident, $method_name:literal, $args:expr) => {
            call_by_with_arg($account, &$contract, $method_name, $args)
        };
    }

    #[tokio::test]
    async fn test_verify_bls_signature() {
        let (_, contract) = get_contract(WASM_FILEPATH).await;
        assert!(call!(contract, "new").await);

        let config = get_config();
        let light_client_updates: Vec<LightClientUpdate> = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_light_client_updates)
                .expect("Unable to read file"),
        )
            .unwrap();
        let current_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_current_sync_committee.clone())
                .expect("Unable to read file"),
        )
            .unwrap();
        let next_sync_committee: SyncCommittee = serde_json::from_str(
            &std::fs::read_to_string(config.path_to_next_sync_committee.clone())
                .expect("Unable to read file"),
        )
            .unwrap();

        let sync_committee_bits = BitVec::<u8, Lsb0>::from_slice(
            &light_client_updates[0]
                .sync_aggregate
                .sync_committee_bits
                .0,
        );

        let participant_pubkeys =
            get_participant_pubkeys(&current_sync_committee.pubkeys.0, &sync_committee_bits);

        let mut pubks: Vec<Vec<u8>> = vec![];
        for pk in participant_pubkeys {
            pubks.push(pk.0.to_vec());
        }

        let ethereum_network = Network::from_str("goerli").unwrap();
        let network_config = NetworkConfig::new(&ethereum_network);

        let fork_version = network_config
            .compute_fork_version_by_slot(light_client_updates[0].signature_slot)
            .expect("Unsupported fork");

        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE,
            fork_version,
            network_config.genesis_validators_root.into(),
        );

        let signing_root = compute_signing_root(
            eth_types::H256(
                light_client_updates[0]
                    .attested_beacon_header
                    .tree_hash_root(),
            ),
            domain,
        );

        //let res = contract.call("verify_bls_signature").args_json(json!({"msg": signing_root.0.as_bytes(), "signature": light_client_updates[0].sync_aggregate.sync_committee_signature.0.to_vec(), "pubkeys": pubks})).max_gas().transact().await.unwrap();
        //println!("{:?}", res);
    }

    #[derive(Debug, Clone)]
    pub struct ConfigForTests {
        pub path_to_current_sync_committee: String,
        pub path_to_next_sync_committee: String,
        pub path_to_light_client_updates: String,
        pub network_name: String,
    }

    fn get_config() -> ConfigForTests {
        ConfigForTests {
            path_to_current_sync_committee: "./data/next_sync_committee_goerli_period_473.json"
                .to_string(),
            path_to_next_sync_committee: "./data/next_sync_committee_goerli_period_474.json"
                .to_string(),
            path_to_light_client_updates:
            "./data/light_client_updates_goerli_slots_3885697_3886176.json".to_string(),
            network_name: "goerli".to_string(),
        }
    }

    pub async fn get_contract(wasm_path: &str) -> (Account, Contract) {
        let worker = workspaces::sandbox().await.unwrap();

        let owner = worker.root_account().unwrap();

        let wasm = std::fs::read(wasm_path).unwrap();
        let contract = owner.deploy(&wasm).await.unwrap().unwrap();

        (owner, contract)
    }

    pub async fn call_arg(contract: &Contract, method_name: &str, args: &serde_json::Value) -> bool {
        let res = contract
            .call(method_name)
            .args_json(args)
            .max_gas()
            .transact()
            .await.unwrap();
        res.is_success()
    }

    pub async fn call_by_with_arg(account: &Account, contract: &Contract, method_name: &str, args: &serde_json::Value) -> bool {
        account.call(contract.id(), method_name)
            .args_json(args)
            .max_gas()
            .transact()
            .await.unwrap().is_success()
    }

    pub fn get_participant_pubkeys(
        public_keys: &[PublicKeyBytes],
        sync_committee_bits: &BitVec<u8, Lsb0>,
    ) -> Vec<PublicKeyBytes> {
        let mut result: Vec<PublicKeyBytes> = vec![];
        for (idx, bit) in sync_committee_bits.iter().by_vals().enumerate() {
            if bit {
                result.push(public_keys[idx].clone());
            }
        }
        result
    }
}