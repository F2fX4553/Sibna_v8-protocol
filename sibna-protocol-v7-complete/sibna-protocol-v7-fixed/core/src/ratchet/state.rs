//! Double Ratchet State
//!
//! Manages the state for the Double Ratchet algorithm.

use super::ChainKey;
use x25519_dalek::{PublicKey, StaticSecret};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;

/// Double Ratchet State
///
/// Contains all state needed for the Double Ratchet algorithm.
/// This includes:
/// - Root key for DH ratchet
/// - Sending and receiving chain keys
/// - DH key pairs
/// - Skipped message keys for out-of-order handling
#[derive(Serialize, Deserialize)]
pub struct DoubleRatchetState {
    /// Root key for KDF chain
    pub root_key: [u8; 32],

    /// Sending chain key
    pub sending_chain: Option<ChainKey>,

    /// Receiving chain key
    pub receiving_chain: Option<ChainKey>,

    /// Local DH private key (X25519)
    #[serde(skip)]
    pub dh_local: Option<StaticSecret>,

    /// Serialized local DH public key bytes
    #[serde(with = "serde_bytes")]
    pub dh_local_bytes: Vec<u8>,

    /// Remote DH public key
    #[serde(skip)]
    pub dh_remote: Option<PublicKey>,

    /// Skipped message keys for out-of-order messages
    /// Key: (public_key_bytes, message_number)
    /// Value: message_key
    #[serde(with = "skipped_keys_serde")]
    pub skipped_message_keys: HashMap<([u8; 32], u64), [u8; 32]>,

    /// Maximum number of skipped messages to store
    #[serde(skip)]
    pub max_skip: usize,

    /// Previous chain length for header
    pub previous_counter: u64,
}

impl Clone for DoubleRatchetState {
    fn clone(&self) -> Self {
        // Manual clone because StaticSecret doesn't derive Clone
        let dh_local_clone = self.dh_local.as_ref().map(|dh| {
            let bytes = dh.to_bytes();
            StaticSecret::from(bytes)
        });

        Self {
            root_key: self.root_key,
            sending_chain: self.sending_chain.clone(),
            receiving_chain: self.receiving_chain.clone(),
            dh_local: dh_local_clone,
            dh_local_bytes: self.dh_local_bytes.clone(),
            dh_remote: self.dh_remote,
            skipped_message_keys: self.skipped_message_keys.clone(),
            max_skip: self.max_skip,
            previous_counter: self.previous_counter,
        }
    }
}

impl Zeroize for DoubleRatchetState {
    fn zeroize(&mut self) {
        self.root_key.zeroize();
        self.sending_chain = None;
        self.receiving_chain = None;
        self.dh_local = None;
        self.dh_local_bytes.zeroize();
        self.dh_remote = None;
        self.skipped_message_keys.clear();
        self.previous_counter = 0;
    }
}

impl ZeroizeOnDrop for DoubleRatchetState {}

/// Custom serialization for skipped message keys
mod skipped_keys_serde {
    use super::*;
    use serde::{Serialize, Deserialize, Serializer, Deserializer};

    #[derive(Serialize, Deserialize)]
    struct SkippedKeyEntry {
        pub_key: [u8; 32],
        msg_num: u64,
        msg_key: [u8; 32],
    }

    pub fn serialize<S>(map: &HashMap<([u8; 32], u64), [u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<SkippedKeyEntry> = map
            .iter()
            .map(|((pub_key, msg_num), msg_key)| SkippedKeyEntry {
                pub_key: *pub_key,
                msg_num: *msg_num,
                msg_key: *msg_key,
            })
            .collect();

        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<([u8; 32], u64), [u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries: Vec<SkippedKeyEntry> = Vec::deserialize(deserializer)?;

        let mut map = HashMap::new();
        for entry in entries {
            map.insert((entry.pub_key, entry.msg_num), entry.msg_key);
        }

        Ok(map)
    }
}

/// Custom serialization for bytes
mod serde_bytes {
    use serde::{Serializer, Deserializer, de::Error};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(bytes)
    }
}
