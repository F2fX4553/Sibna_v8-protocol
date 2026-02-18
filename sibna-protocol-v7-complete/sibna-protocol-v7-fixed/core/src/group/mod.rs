//! Group Messaging - Sender Keys Implementation
//!
//! Implements the Sender Keys protocol for efficient group encryption.
//! Based on Signal's group messaging design.

use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::{CryptoHandler, SecureRandom, KEY_LENGTH};

/// Group ID type
pub type GroupId = [u8; 32];

/// Sender Key for group messaging
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKey {
    /// Chain key for message derivation
    pub chain_key: [u8; 32],
    /// Current message number
    pub message_number: u32,
    /// Expiration timestamp
    pub expiration: Option<u64>,
}

impl SenderKey {
    /// Create a new sender key
    pub fn new() -> ProtocolResult<Self> {
        let mut rng = SecureRandom::new()?;
        let mut chain_key = [0u8; 32];
        rng.fill_bytes(&mut chain_key);

        Ok(Self {
            chain_key,
            message_number: 0,
            expiration: None,
        })
    }

    /// Derive next message key
    pub fn next_message_key(&mut self) -> ProtocolResult<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);
        
        // Derive message key
        let mut message_key = [0u8; 32];
        hkdf.expand(b"message_key", &mut message_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
        
        // Advance chain key
        let mut next_chain = [0u8; 32];
        hkdf.expand(b"chain_key", &mut next_chain)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
        
        self.chain_key = next_chain;
        self.message_number += 1;
        
        Ok(message_key)
    }
}

/// Sender Key Distribution Message
#[derive(Serialize, Deserialize)]
pub struct SenderKeyMessage {
    /// Group ID
    pub group_id: GroupId,
    /// Sender's public key
    pub sender_public_key: [u8; 32],
    /// Encrypted sender key
    pub encrypted_key: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Group Session State
pub struct GroupSession {
    /// Group ID
    pub group_id: GroupId,
    /// Our sender key for this group
    pub our_sender_key: Option<SenderKey>,
    /// Sender keys from other members (public_key -> key)
    pub sender_keys: HashMap<[u8; 32], SenderKey>,
    /// Group members' public keys
    pub members: Vec<[u8; 32]>,
    /// Current epoch (incremented on member change)
    pub epoch: u64,
    /// Group name (optional)
    pub name: Option<String>,
}

impl GroupSession {
    /// Create a new group session
    pub fn new(group_id: GroupId) -> Self {
        Self {
            group_id,
            our_sender_key: None,
            sender_keys: HashMap::new(),
            members: Vec::new(),
            epoch: 0,
            name: None,
        }
    }

    /// Initialize sender key for this group
    pub fn initialize_sender_key(&mut self) -> ProtocolResult<()> {
        self.our_sender_key = Some(SenderKey::new()?);
        Ok(())
    }

    /// Add a member to the group
    pub fn add_member(&mut self, public_key: [u8; 32]) {
        if !self.members.contains(&public_key) {
            self.members.push(public_key);
            self.epoch += 1;
        }
    }

    /// Remove a member from the group
    pub fn remove_member(&mut self, public_key: &[u8; 32]) {
        self.members.retain(|k| k != public_key);
        self.sender_keys.remove(public_key);
        self.epoch += 1;
    }

    /// Encrypt a group message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> ProtocolResult<GroupMessage> {
        let sender_key = self.our_sender_key.as_mut()
            .ok_or_else(|| ProtocolError::InvalidState("No sender key".into()))?;
        
        let message_key = sender_key.next_message_key()?;
        
        let crypto = CryptoHandler::new(&message_key)?;
        let ciphertext = crypto.encrypt(plaintext, &self.group_id)?;
        
        Ok(GroupMessage {
            group_id: self.group_id,
            sender_key_id: 0, // Our key
            message_number: sender_key.message_number - 1,
            ciphertext,
            epoch: self.epoch,
        })
    }

    /// Decrypt a group message
    pub fn decrypt(&mut self, message: &GroupMessage, sender_public_key: &[u8; 32]) -> ProtocolResult<Vec<u8>> {
        let sender_key = self.sender_keys.get_mut(sender_public_key)
            .ok_or_else(|| ProtocolError::InvalidState("No sender key for this member".into()))?;
        
        // Derive message keys until we reach the target
        while sender_key.message_number < message.message_number {
            sender_key.next_message_key()?;
        }
        
        let message_key = sender_key.next_message_key()?;
        let crypto = CryptoHandler::new(&message_key)?;
        
        crypto.decrypt(&message.ciphertext, &self.group_id)
            .map_err(ProtocolError::from)
    }

    /// Import a sender key from another member
    pub fn import_sender_key(&mut self, public_key: [u8; 32], key: SenderKey) {
        self.sender_keys.insert(public_key, key);
    }
}

/// Group Message
#[derive(Serialize, Deserialize)]
pub struct GroupMessage {
    /// Group ID
    pub group_id: GroupId,
    /// Sender key identifier
    pub sender_key_id: u32,
    /// Message number
    pub message_number: u32,
    /// Encrypted content
    pub ciphertext: Vec<u8>,
    /// Group epoch
    pub epoch: u64,
}

/// Group Manager - Handles multiple groups
pub struct GroupManager {
    groups: HashMap<GroupId, GroupSession>,
    crypto: CryptoHandler,
}

impl GroupManager {
    /// Create a new group manager
    pub fn new(master_key: &[u8; 32]) -> ProtocolResult<Self> {
        Ok(Self {
            groups: HashMap::new(),
            crypto: CryptoHandler::new(master_key)?,
        })
    }

    /// Create a new group
    pub fn create_group(&mut self, group_id: GroupId) -> ProtocolResult<&mut GroupSession> {
        let mut session = GroupSession::new(group_id);
        session.initialize_sender_key()?;
        
        self.groups.insert(group_id, session);
        Ok(self.groups.get_mut(&group_id).unwrap())
    }

    /// Get a group session
    pub fn get_group(&self, group_id: &GroupId) -> Option<&GroupSession> {
        self.groups.get(group_id)
    }

    /// Get a mutable group session
    pub fn get_group_mut(&mut self, group_id: &GroupId) -> Option<&mut GroupSession> {
        self.groups.get_mut(group_id)
    }

    /// Leave a group
    pub fn leave_group(&mut self, group_id: &GroupId) {
        self.groups.remove(group_id);
    }

    /// List all groups
    pub fn list_groups(&self) -> Vec<&GroupId> {
        self.groups.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_key_creation() {
        let key = SenderKey::new();
        assert!(key.is_ok());
    }

    #[test]
    fn test_sender_key_derivation() {
        let mut key = SenderKey::new().unwrap();
        
        let mk1 = key.next_message_key().unwrap();
        let mk2 = key.next_message_key().unwrap();
        
        assert_ne!(mk1, mk2);
        assert_eq!(key.message_number, 2);
    }

    #[test]
    fn test_group_session_creation() {
        let group_id = [0u8; 32];
        let mut session = GroupSession::new(group_id);
        
        assert!(session.initialize_sender_key().is_ok());
        assert!(session.our_sender_key.is_some());
    }

    #[test]
    fn test_group_encryption() {
        let group_id = [0x42u8; 32];
        let mut session = GroupSession::new(group_id);
        session.initialize_sender_key().unwrap();
        
        let plaintext = b"Hello Group!";
        let message = session.encrypt(plaintext);
        
        assert!(message.is_ok());
    }
}
