//! Double Ratchet Session
//!
//! Main session implementation for the Double Ratchet algorithm.

use super::{ChainKey, DoubleRatchetState};
use crate::crypto::{Encryptor, CryptoError};
use crate::error::{ProtocolError, ProtocolResult};
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use parking_lot::RwLock;
use std::collections::HashMap;
use rand_core::OsRng;

/// Double Ratchet Session
///
/// Manages a single secure communication session with a peer.
pub struct DoubleRatchetSession {
    state: RwLock<DoubleRatchetState>,
    config: Config,
}

impl DoubleRatchetSession {
    /// Create a new session with default state
    ///
    /// # Arguments
    /// * `config` - Configuration options
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let dh_local = StaticSecret::random_from_rng(&mut OsRng);
        let dh_local_bytes = dh_local.to_bytes().to_vec();

        let state = DoubleRatchetState {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: Some(dh_local),
            dh_local_bytes,
            dh_remote: None,
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
        };

        Ok(Self {
            state: RwLock::new(state),
            config,
        })
    }

    /// Create a session from a shared secret (post-handshake)
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte shared secret from X3DH
    /// * `local_dh` - Local DH key pair
    /// * `remote_dh` - Remote DH public key
    /// * `config` - Configuration options
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        local_dh: StaticSecret,
        remote_dh: PublicKey,
        config: Config,
    ) -> ProtocolResult<Self> {
        // Derive initial keys from shared secret
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);

        let mut root_key = [0u8; 32];
        hkdf.expand(b"root_key", &mut root_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let mut sending_key = [0u8; 32];
        hkdf.expand(b"sending_chain", &mut sending_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let sending_chain = ChainKey::new(sending_key);
        let dh_local_bytes = local_dh.to_bytes().to_vec();

        let state = DoubleRatchetState {
            root_key,
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            dh_local: Some(local_dh),
            dh_local_bytes,
            dh_remote: Some(remote_dh),
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
        };

        Ok(Self {
            state: RwLock::new(state),
            config,
        })
    }

    /// Encrypt a message
    ///
    /// # Arguments
    /// * `plaintext` - Message to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The encrypted message: header || ciphertext
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let mut state = self.state.write();

        let sending_chain = state.sending_chain.as_mut()
            .ok_or_else(|| ProtocolError::InvalidState("No sending chain".to_string()))?;

        // Derive message key
        let message_key = sending_chain.next_message_key();

        // Build header
        let dh_pub = state.dh_local.as_ref()
            .map(PublicKey::from)
            .ok_or_else(|| ProtocolError::InvalidState("No local DH key".to_string()))?;

        let mut header = Vec::with_capacity(32 + 8 + 8);
        header.extend_from_slice(dh_pub.as_bytes());
        header.extend_from_slice(&(sending_chain.index - 1).to_le_bytes());
        header.extend_from_slice(&state.previous_counter.to_le_bytes());

        // Encrypt with message key
        let encryptor = Encryptor::new(&message_key, u64::MAX)
            .map_err(ProtocolError::from)?;

        // Build final associated data
        let mut final_ad = Vec::new();
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(&header);

        let ciphertext = encryptor.encrypt_message(plaintext, &final_ad)?;

        // Combine header and ciphertext
        let mut result = Vec::with_capacity(header.len() + ciphertext.len());
        result.extend_from_slice(&header);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a message
    ///
    /// # Arguments
    /// * `message` - Encrypted message
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(&mut self, message: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        // Minimum size: header (48 bytes) + nonce (12 bytes) + tag (16 bytes)
        if message.len() < 76 {
            return Err(ProtocolError::InvalidMessage("Message too short".to_string()));
        }

        // Parse header
        let header_dh = &message[..32];
        let n = u64::from_le_bytes(
            message[32..40].try_into()
                .map_err(|_| ProtocolError::InvalidMessage("Invalid message number".to_string()))?
        );
        let _pn = u64::from_le_bytes(
            message[40..48].try_into()
                .map_err(|_| ProtocolError::InvalidMessage("Invalid previous counter".to_string()))?
        );
        let ciphertext = &message[48..];
        let header_bytes = &message[..48];

        let mut state = self.state.write();
        let remote_dh = PublicKey::from(
            <[u8; 32]>::try_from(header_dh)
                .map_err(|_| ProtocolError::InvalidMessage("Invalid DH key".to_string()))?
        );

        // 1. Try skipped message keys first
        let key_tuple = (remote_dh.as_bytes().clone(), n);
        if let Some(mk) = state.skipped_message_keys.remove(&key_tuple) {
            let encryptor = Encryptor::new(&mk, u64::MAX)
                .map_err(ProtocolError::from)?;

            let mut ad = Vec::from(associated_data);
            ad.extend_from_slice(header_bytes);

            return encryptor.decrypt_message(ciphertext, &ad)
                .map_err(ProtocolError::from);
        }

        // 2. Check if DH ratchet is needed
        let needs_ratchet = match state.dh_remote {
            None => true,
            Some(ref current) => *current != remote_dh,
        };

        if needs_ratchet {
            self.skip_message_keys(&mut state, _pn)?;
            self.dh_ratchet(&mut state, remote_dh)?;
        }

        // 3. Skip to current message
        self.skip_message_keys(&mut state, n)?;

        // 4. Get message key from receiving chain
        let mk = if let Some(ref mut receiving_chain) = state.receiving_chain {
            if n < receiving_chain.index {
                return Err(ProtocolError::ReplayAttackDetected);
            }

            // Skip any remaining messages
            while receiving_chain.index < n + 1 {
                let skipped_mk = receiving_chain.next_message_key();
                let dh_remote = state.dh_remote
                    .ok_or_else(|| ProtocolError::InvalidState("No remote DH".to_string()))?;

                state.skipped_message_keys.insert(
                    (dh_remote.as_bytes().clone(), receiving_chain.index - 1),
                    skipped_mk
                );

                if state.skipped_message_keys.len() > state.max_skip {
                    return Err(ProtocolError::MaxSkippedMessagesExceeded);
                }
            }

            receiving_chain.next_message_key()
        } else {
            return Err(ProtocolError::InvalidState("No receiving chain".to_string()));
        };

        // 5. Decrypt
        let encryptor = Encryptor::new(&mk, u64::MAX)
            .map_err(ProtocolError::from)?;

        let mut final_ad = Vec::from(associated_data);
        final_ad.extend_from_slice(header_bytes);

        encryptor.decrypt_message(ciphertext, &final_ad)
            .map_err(ProtocolError::from)
    }

    /// Skip message keys up to a certain number
    fn skip_message_keys(
        &self,
        state: &mut DoubleRatchetState,
        until_n: u64,
    ) -> ProtocolResult<()> {
        if let Some(ref mut chain) = state.receiving_chain {
            // Check limit
            if until_n > chain.index + self.config.max_skipped_messages as u64 {
                return Err(ProtocolError::MaxSkippedMessagesExceeded);
            }

            // Store keys for skipped messages
            while chain.index < until_n {
                let mk = chain.next_message_key();
                let dh_remote = state.dh_remote
                    .ok_or_else(|| ProtocolError::InvalidState("No remote DH".to_string()))?;

                state.skipped_message_keys.insert(
                    (dh_remote.as_bytes().clone(), chain.index - 1),
                    mk
                );

                if state.skipped_message_keys.len() > state.config.max_skipped_messages {
                    return Err(ProtocolError::MaxSkippedMessagesExceeded);
                }
            }
        }
        Ok(())
    }

    /// Perform a DH ratchet step
    fn dh_ratchet(
        &self,
        state: &mut DoubleRatchetState,
        remote_dh: PublicKey,
    ) -> ProtocolResult<()> {
        // Update previous counter
        state.previous_counter = state.sending_chain.as_ref()
            .map(|c| c.index)
            .unwrap_or(0);

        // Update remote key
        state.dh_remote = Some(remote_dh);

        // Receiving ratchet
        let dh_local = state.dh_local.as_ref()
            .ok_or_else(|| ProtocolError::InvalidState("No local DH".to_string()))?;

        let shared_secret = dh_local.diffie_hellman(&remote_dh);
        let (root_key, receiving_key) = self.kdf_rk(&state.root_key, shared_secret.as_bytes())?;

        state.root_key = root_key;
        state.receiving_chain = Some(ChainKey::new(receiving_key));

        // Generate new local key pair
        let new_local = StaticSecret::random_from_rng(&mut OsRng);

        // Sending ratchet
        let shared_secret_send = new_local.diffie_hellman(&remote_dh);
        let (root_key, sending_key) = self.kdf_rk(&state.root_key, shared_secret_send.as_bytes())?;

        state.root_key = root_key;
        state.sending_chain = Some(ChainKey::new(sending_key));
        state.dh_local = Some(new_local);
        state.dh_local_bytes = state.dh_local.as_ref().unwrap().to_bytes().to_vec();

        Ok(())
    }

    /// KDF for root key
    fn kdf_rk(
        &self,
        root_key: &[u8; 32],
        dh_out: &[u8; 32],
    ) -> ProtocolResult<([u8; 32], [u8; 32])> {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_out);

        let mut okm = [0u8; 64];
        hkdf.expand(b"ratchet_step", &mut okm)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        let mut new_rk = [0u8; 32];
        let mut new_ck = [0u8; 32];
        new_rk.copy_from_slice(&okm[..32]);
        new_ck.copy_from_slice(&okm[32..]);

        Ok((new_rk, new_ck))
    }

    /// Serialize session state
    pub fn serialize_state(&self) -> ProtocolResult<Vec<u8>> {
        let state = self.state.read();
        serde_json::to_vec(&*state)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }

    /// Deserialize session state
    pub fn deserialize_state(&mut self, data: &[u8]) -> ProtocolResult<()> {
        let mut state = self.state.write();

        let mut loaded: DoubleRatchetState = serde_json::from_slice(data)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))?;

        // Restore StaticSecret from bytes
        if !loaded.dh_local_bytes.is_empty() {
            let arr: [u8; 32] = loaded.dh_local_bytes.clone()
                .try_into()
                .map_err(|_| ProtocolError::DeserializationError("Invalid DH bytes length".to_string()))?;
            loaded.dh_local = Some(StaticSecret::from(arr));
        }

        loaded.max_skip = self.config.max_skipped_messages;
        *state = loaded;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let config = Config::default();
        let session = DoubleRatchetSession::new(config);
        assert!(session.is_ok());
    }

    #[test]
    fn test_session_from_shared_secret() {
        let config = Config::default();
        let shared_secret = [0x42u8; 32];
        let local_dh = StaticSecret::random_from_rng(&mut OsRng);
        let remote_dh = PublicKey::from(&StaticSecret::random_from_rng(&mut OsRng));

        let session = DoubleRatchetSession::from_shared_secret(
            &shared_secret,
            local_dh,
            remote_dh,
            config,
        );

        assert!(session.is_ok());
    }

    #[test]
    fn test_encrypt_without_sending_chain() {
        let config = Config::default();
        let mut session = DoubleRatchetSession::new(config).unwrap();

        let result = session.encrypt(b"test", b"ad");
        assert!(result.is_err());
    }

    #[test]
    fn test_state_serialization() {
        let config = Config::default();
        let session = DoubleRatchetSession::new(config).unwrap();

        let serialized = session.serialize_state();
        assert!(serialized.is_ok());

        let mut new_session = DoubleRatchetSession::new(Config::default()).unwrap();
        let result = new_session.deserialize_state(&serialized.unwrap());
        assert!(result.is_ok());
    }
}
