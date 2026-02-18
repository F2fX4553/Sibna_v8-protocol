//! Chain Key Implementation
//!
//! Implements the symmetric ratchet chain keys for message key derivation.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

/// Message key seed constant
const MESSAGE_KEY_SEED: u8 = 0x01;

/// Chain key seed constant
const CHAIN_KEY_SEED: u8 = 0x02;

/// Chain Key for Double Ratchet
///
/// Each chain key can derive message keys and the next chain key.
/// This provides forward secrecy within a single chain.
#[derive(Serialize, Deserialize)]
pub struct ChainKey {
    /// The chain key value
    pub key: [u8; 32],
    /// Current message number in this chain
    pub index: u64,
    #[serde(skip)]
    hmac: Option<Hmac<Sha256>>,
}

// Implement zeroize manually due to HMAC not implementing Zeroize
impl Zeroize for ChainKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.index = 0;
        self.hmac = None;
    }
}

impl ZeroizeOnDrop for ChainKey {}

impl Clone for ChainKey {
    fn clone(&self) -> Self {
        // Re-create HMAC on clone
        let hmac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC key length is valid");

        Self {
            key: self.key,
            index: self.index,
            hmac: Some(hmac),
        }
    }
}

impl ChainKey {
    /// Create a new chain key from raw bytes
    ///
    /// # Arguments
    /// * `key` - 32-byte chain key value
    pub fn new(key: [u8; 32]) -> Self {
        let hmac = Hmac::<Sha256>::new_from_slice(&key)
            .expect("HMAC key length is valid");

        Self {
            key,
            index: 0,
            hmac: Some(hmac),
        }
    }

    /// Derive the next message key
    ///
    /// This also advances the chain key to the next state.
    ///
    /// # Returns
    /// A 32-byte message key
    pub fn next_message_key(&mut self) -> [u8; 32] {
        // Derive message key: MK = HMAC(CK, 0x01)
        let message_key = self.derive_key(MESSAGE_KEY_SEED);

        // Advance chain key: CK' = HMAC(CK, 0x02)
        let next_key = self.derive_key(CHAIN_KEY_SEED);

        // Update state
        self.key = next_key;
        self.hmac = Some(Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC valid"));
        self.index += 1;

        message_key
    }

    /// Derive a key from the current chain key
    fn derive_key(&self, seed: u8) -> [u8; 32] {
        let mut hmac = self.hmac.clone().expect("HMAC initialized");
        hmac.update(&[seed]);
        let result = hmac.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result.into_bytes()[..32]);

        key
    }

    /// Get the current index without advancing
    pub fn index(&self) -> u64 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation() {
        let key = [0x42u8; 32];
        let mut chain = ChainKey::new(key);

        let mk1 = chain.next_message_key();
        let mk2 = chain.next_message_key();
        let mk3 = chain.next_message_key();

        // Each message key should be different
        assert_ne!(mk1, mk2);
        assert_ne!(mk2, mk3);
        assert_ne!(mk1, mk3);

        // Index should advance
        assert_eq!(chain.index, 3);
    }

    #[test]
    fn test_chain_key_clone() {
        let key = [0x42u8; 32];
        let chain1 = ChainKey::new(key);
        let chain2 = chain1.clone();

        // Keys should match
        assert_eq!(chain1.key, chain2.key);
        assert_eq!(chain1.index, chain2.index);
    }
}
