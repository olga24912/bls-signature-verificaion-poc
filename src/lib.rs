use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use near_sdk::serde::{Deserialize, Serialize};

#[near_bindgen]
#[derive(Default, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
struct BLSVerificationPOC {}

#[near_bindgen]
impl BLSVerificationPOC {
    #[init]
    #[payable]
    pub fn new() -> Self { Self {} }

    pub fn verify_bls_signature(&self,
                                #[serializer(borsh)] msg: Vec<u8>,
                                #[serializer(borsh)] signature: Vec<u8>,
                                #[serializer(borsh)] pubkeys: Vec<Vec<u8>>) -> bool {
        return true
    }
}

#[cfg(test)]
mod tests {
}