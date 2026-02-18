//! Sibna Core - Secure Communication Protocol Kernel
//!
//! A professional, production-ready implementation of the Signal Protocol
//! for secure end-to-end encrypted communication.
//!
//! # Features
//! - X3DH Key Agreement Protocol
//! - Double Ratchet Algorithm
//! - Group Messaging (Sender Keys)
//! - Multi-device Synchronization
//! - Forward Secrecy & Post-Compromise Security
//! - WASM Support
//!
//! # Version
//! 7.0.0 - Production Ready

#![warn(missing_docs)]
#![warn(unsafe_op_in_unsafe_fn)]
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_clone)]

// System Modules
pub mod crypto;
pub mod ratchet;
pub mod handshake;
pub mod keystore;
pub mod error;
pub mod group;
pub mod safety;
pub mod rate_limit;
pub mod validation;

// FFI Modules
#[cfg(feature = "ffi")]
pub mod ffi;

// WASM Module
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Re-exports
pub use crypto::*;
pub use ratchet::*;
pub use handshake::*;
pub use keystore::*;
pub use error::{ProtocolError, ProtocolResult};
pub use group::{GroupSession, GroupManager, SenderKey, GroupMessage};
pub use safety::{SafetyNumber, VerificationQrCode};
pub use rate_limit::{RateLimiter, RateLimitError, OperationLimit, RemainingQuota};
pub use validation::{validate_message, validate_key, validate_session_id, ValidationError};

use std::sync::Arc;
use parking_lot::RwLock;
use std::path::PathBuf;

/// Protocol version
pub const VERSION: &str = "7.0.0";

/// Main System Context for secure communication
///
/// This is the primary entry point for the Sibna protocol. It manages
/// key storage, session state, group messaging, and cryptographic operations.
#[derive(Clone)]
pub struct SecureContext {
    /// Encrypted key storage
    keystore: Arc<RwLock<KeyStore>>,
    /// Session manager for active connections
    sessions: Arc<RwLock<SessionManager>>,
    /// Group manager for group messaging
    groups: Arc<RwLock<GroupManager>>,
    /// Configuration options
    config: Config,
    /// Secure random number generator
    random: Arc<RwLock<SecureRandom>>,
    /// Storage encryption key (never exposed)
    storage_key: [u8; 32],
    /// Device ID for multi-device sync
    device_id: [u8; 16],
}

/// System Configuration
///
/// Controls various security and performance parameters for the protocol.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Enable Forward Secrecy (recommended: true)
    pub enable_forward_secrecy: bool,
    /// Enable Post-Compromise Security (recommended: true)
    pub enable_post_compromise_security: bool,
    /// Maximum number of skipped messages to store
    pub max_skipped_messages: usize,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Handshake timeout in seconds
    pub handshake_timeout: u64,
    /// Message buffer size
    pub message_buffer_size: usize,
    /// Enable group messaging
    pub enable_group_messaging: bool,
    /// Maximum group size
    pub max_group_size: usize,
    /// Database path
    pub db_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_forward_secrecy: true,
            enable_post_compromise_security: true,
            max_skipped_messages: 2000,
            key_rotation_interval: 86400, // 24 hours
            handshake_timeout: 30,
            message_buffer_size: 1024,
            enable_group_messaging: true,
            max_group_size: 256,
            db_path: None,
        }
    }
}

impl SecureContext {
    /// Create a new secure context with the given configuration
    ///
    /// # Arguments
    /// * `config` - Configuration options
    /// * `master_password` - Optional master password for storage encryption
    ///
    /// # Returns
    /// A new SecureContext instance or an error
    ///
    /// # Security Note
    /// If no master password is provided, a random key is generated.
    pub fn new(config: Config, master_password: Option<&[u8]>) -> ProtocolResult<Self> {
        // Derive storage key from password or generate random
        let mut storage_key = [0u8; 32];
        if let Some(password) = master_password {
            if password.is_empty() {
                return Err(ProtocolError::InvalidArgument("Password cannot be empty".to_string()));
            }
            let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, password);
            hkdf.expand(b"sibna_storage_key_v7", &mut storage_key)
                .map_err(|_| ProtocolError::KeyDerivationFailed)?;
        } else {
            let mut rng = SecureRandom::new()?;
            rng.fill_bytes(&mut storage_key);
        }

        // Generate device ID
        let mut device_id = [0u8; 16];
        let mut rng = SecureRandom::new()?;
        rng.fill_bytes(&mut device_id);

        // Open database
        let db_path = config.db_path.clone()
            .unwrap_or_else(|| "sibna_secure_db".to_string());
        let db = sled::open(&db_path)
            .map_err(|e| ProtocolError::InternalError(format!("Database open error: {}", e)))?;
        let db_arc = Arc::new(db);

        let keystore = KeyStore::new(db_arc.clone(), storage_key)?;
        let sessions = SessionManager::new(config.clone(), db_arc.clone(), storage_key);
        let groups = GroupManager::new(&storage_key)?;
        let random = SecureRandom::new()?;

        Ok(Self {
            keystore: Arc::new(RwLock::new(keystore)),
            sessions: Arc::new(RwLock::new(sessions)),
            groups: Arc::new(RwLock::new(groups)),
            config,
            random: Arc::new(RwLock::new(random)),
            storage_key,
            device_id,
        })
    }

    /// Create an in-memory context (for WASM/testing)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory(config: Config) -> ProtocolResult<Self> {
        let mut storage_key = [0u8; 32];
        let mut rng = SecureRandom::new()?;
        rng.fill_bytes(&mut storage_key);

        let mut device_id = [0u8; 16];
        rng.fill_bytes(&mut device_id);

        let groups = GroupManager::new(&storage_key)?;
        let random = SecureRandom::new()?;

        // Note: In WASM, we use memory storage
        Ok(Self {
            keystore: Arc::new(RwLock::new(KeyStore::new_in_memory()?)),
            sessions: Arc::new(RwLock::new(SessionManager::new_in_memory(config.clone())?)),
            groups: Arc::new(RwLock::new(groups)),
            config,
            random: Arc::new(RwLock::new(random)),
            storage_key,
            device_id,
        })
    }

    /// Get the device ID
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Create a new session with a peer
    pub fn create_session(&self, peer_id: &[u8]) -> ProtocolResult<SessionHandle> {
        let mut sessions = self.sessions.write();
        sessions.create_session(peer_id, self.config.clone())
    }

    /// Load an identity key pair into the keystore
    pub fn load_identity(&mut self, ed_pub: &[u8], x_pub: &[u8], seed: &[u8]) -> ProtocolResult<()> {
        if ed_pub.len() != 32 || x_pub.len() != 32 || seed.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }

        let keypair = crate::keystore::IdentityKeyPair::from_bytes(ed_pub, x_pub, seed);
        self.keystore.write().set_identity(keypair)
    }

    /// Generate a new identity
    pub fn generate_identity(&mut self) -> ProtocolResult<IdentityKeyPair> {
        let keypair = IdentityKeyPair::generate();
        self.keystore.write().set_identity(keypair.clone())?;
        Ok(keypair)
    }

    /// Get the current identity
    pub fn get_identity(&self) -> ProtocolResult<IdentityKeyPair> {
        self.keystore.read().get_identity_keypair()
    }

    /// Perform X3DH handshake with a peer
    #[allow(clippy::too_many_arguments)]
    pub fn perform_handshake(
        &self,
        peer_id: &[u8],
        initiator: bool,
        peer_identity_key: Option<&[u8]>,
        peer_signed_prekey: Option<&[u8]>,
        peer_onetime_prekey: Option<&[u8]>,
        prologue: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let keystore = self.keystore.read();
        let random = self.random.read();

        let mut builder = HandshakeBuilder::new()
            .with_config(self.config.clone())
            .with_keystore(&*keystore)
            .with_random(&*random)
            .with_initiator(initiator);

        if let Some(pk) = peer_identity_key {
            builder = builder.with_peer_identity_key(pk)?;
        }
        if let Some(spk) = peer_signed_prekey {
            builder = builder.with_peer_signed_prekey(spk)?;
        }
        if let Some(opk) = peer_onetime_prekey {
            builder = builder.with_peer_onetime_prekey(opk)?;
        }
        if let Some(p) = prologue {
            builder = builder.with_prologue(p);
        }

        let handshake = builder.build()?;
        let output = handshake.perform()?;

        let mut sessions = self.sessions.write();

        let (remote_dh, local_dh) = if initiator {
            let spk = peer_signed_prekey.ok_or(ProtocolError::InvalidState)?;
            let remote_dh = PublicKey::from(
                <[u8; 32]>::try_from(spk).map_err(|_| ProtocolError::InvalidKeyLength)?
            );
            (remote_dh, output.local_ephemeral_key)
        } else {
            let opk = peer_onetime_prekey.ok_or(ProtocolError::InvalidState)?;
            let remote_dh = PublicKey::from(
                <[u8; 32]>::try_from(opk).map_err(|_| ProtocolError::InvalidKeyLength)?
            );
            (remote_dh, output.local_ephemeral_key)
        };

        let session = DoubleRatchetSession::from_shared_secret(
            &output.shared_secret,
            local_dh,
            remote_dh,
            self.config.clone(),
        )?;

        let session_arc = Arc::new(RwLock::new(session));
        sessions.insert_session(peer_id, session_arc.clone());
        sessions.save_session(peer_id, &*session_arc.read())?;

        Ok(output.shared_secret.to_vec())
    }

    /// Encrypt a message for a session
    pub fn encrypt_message(
        &self,
        session_id: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;

        let mut session = session.write();
        let ad = associated_data.unwrap_or_default();

        let res = session.encrypt(plaintext, ad)?;
        sessions.save_session(session_id, &*session)?;

        Ok(res)
    }

    /// Decrypt a message from a session
    pub fn decrypt_message(
        &self,
        session_id: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;

        let mut session = session.write();
        let ad = associated_data.unwrap_or_default();

        let res = session.decrypt(ciphertext, ad)?;
        sessions.save_session(session_id, &*session)?;

        Ok(res)
    }

    /// Create a new group
    pub fn create_group(&self, group_id: [u8; 32]) -> ProtocolResult<()> {
        let mut groups = self.groups.write();
        groups.create_group(group_id)?;
        Ok(())
    }

    /// Encrypt a group message
    pub fn encrypt_group_message(
        &self,
        group_id: &[u8; 32],
        plaintext: &[u8],
    ) -> ProtocolResult<GroupMessage> {
        let mut groups = self.groups.write();
        let group = groups.get_group_mut(group_id)
            .ok_or_else(|| ProtocolError::InvalidState("Group not found".into()))?;
        group.encrypt(plaintext)
    }

    /// Decrypt a group message
    pub fn decrypt_group_message(
        &self,
        message: &GroupMessage,
        sender_public_key: &[u8; 32],
    ) -> ProtocolResult<Vec<u8>> {
        let mut groups = self.groups.write();
        let group = groups.get_group_mut(&message.group_id)
            .ok_or_else(|| ProtocolError::InvalidState("Group not found".into()))?;
        group.decrypt(message, sender_public_key)
    }

    /// Add member to group
    pub fn add_group_member(&self, group_id: &[u8; 32], public_key: [u8; 32]) -> ProtocolResult<()> {
        let mut groups = self.groups.write();
        let group = groups.get_group_mut(group_id)
            .ok_or_else(|| ProtocolError::InvalidState("Group not found".into()))?;
        group.add_member(public_key);
        Ok(())
    }

    /// Remove member from group
    pub fn remove_group_member(&self, group_id: &[u8; 32], public_key: &[u8; 32]) -> ProtocolResult<()> {
        let mut groups = self.groups.write();
        let group = groups.get_group_mut(group_id)
            .ok_or_else(|| ProtocolError::InvalidState("Group not found".into()))?;
        group.remove_member(public_key);
        Ok(())
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Vec<Vec<u8>> {
        self.sessions.read().list_sessions()
    }

    /// List all groups
    pub fn list_groups(&self) -> Vec<[u8; 32]> {
        self.groups.read().list_groups().into_iter().cloned().collect()
    }

    /// Delete a session
    pub fn delete_session(&self, session_id: &[u8]) -> bool {
        self.sessions.write().remove_session(session_id)
    }

    /// Leave a group
    pub fn leave_group(&self, group_id: &[u8; 32]) {
        self.groups.write().leave_group(group_id);
    }
}

/// Session Manager - Handles active sessions and persistence
pub struct SessionManager {
    sessions: RwLock<std::collections::HashMap<Vec<u8>, Arc<RwLock<DoubleRatchetSession>>>>,
    db: Option<sled::Tree>,
    config: Config,
    crypto: crate::crypto::CryptoHandler,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: Config, db: Arc<sled::Db>, storage_key: [u8; 32]) -> ProtocolResult<Self> {
        let tree = db.open_tree("sessions")
            .map_err(|e| ProtocolError::StorageError(format!("Failed to open sessions tree: {}", e)))?;
        let crypto = crate::crypto::CryptoHandler::new(&storage_key)?;

        Ok(Self {
            sessions: RwLock::new(std::collections::HashMap::new()),
            db: Some(tree),
            config,
            crypto,
        })
    }

    /// Create an in-memory session manager (for WASM)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory(config: Config) -> ProtocolResult<Self> {
        let storage_key = [0u8; 32];
        let crypto = crate::crypto::CryptoHandler::new(&storage_key)?;

        Ok(Self {
            sessions: RwLock::new(std::collections::HashMap::new()),
            db: None,
            config,
            crypto,
        })
    }

    /// Create a new session
    pub fn create_session(&mut self, peer_id: &[u8], config: Config) -> ProtocolResult<SessionHandle> {
        let session = DoubleRatchetSession::new(config)?;
        let session = Arc::new(RwLock::new(session));

        if let Some(ref db) = self.db {
            self.save_session(peer_id, &*session.read())?;
        }

        let mut sessions = self.sessions.write();
        sessions.insert(peer_id.to_vec(), session.clone());

        Ok(SessionHandle {
            peer_id: peer_id.to_vec(),
            session,
        })
    }

    /// Get an existing session by ID
    pub fn get_session(&self, session_id: &[u8]) -> ProtocolResult<Arc<RwLock<DoubleRatchetSession>>> {
        {
            let sessions = self.sessions.read();
            if let Some(s) = sessions.get(session_id) {
                return Ok(s.clone());
            }
        }

        if let Some(ref db) = self.db {
            let encrypted = db.get(session_id)
                .map_err(|e| ProtocolError::InternalError(format!("Database read error: {}", e)))?;

            if let Some(data) = encrypted {
                let decrypted = self.crypto.decrypt(&data, session_id)?;
                let mut session = DoubleRatchetSession::new(self.config.clone())?;
                session.deserialize_state(&decrypted)?;

                let arc_s = Arc::new(RwLock::new(session));
                let mut sessions = self.sessions.write();
                sessions.insert(session_id.to_vec(), arc_s.clone());

                return Ok(arc_s);
            }
        }

        Err(ProtocolError::SessionNotFound)
    }

    /// Insert a session into the cache
    pub fn insert_session(&mut self, peer_id: &[u8], session: Arc<RwLock<DoubleRatchetSession>>) {
        let mut sessions = self.sessions.write();
        sessions.insert(peer_id.to_vec(), session);
    }

    /// Save session state
    pub fn save_session(&self, peer_id: &[u8], session: &DoubleRatchetSession) -> ProtocolResult<()> {
        if let Some(ref db) = self.db {
            let state_bytes = session.serialize_state()?;
            let encrypted = self.crypto.encrypt(&state_bytes, peer_id)?;
            db.insert(peer_id, encrypted)?;
            db.flush()?;
        }
        Ok(())
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &[u8]) -> bool {
        let mut sessions = self.sessions.write();
        let removed = sessions.remove(session_id).is_some();
        if let Some(ref db) = self.db {
            let _ = db.remove(session_id);
        }
        removed
    }

    /// List all session IDs
    pub fn list_sessions(&self) -> Vec<Vec<u8>> {
        let sessions = self.sessions.read();
        sessions.keys().cloned().collect()
    }
}

/// Session Handle - Reference to an active session
#[derive(Clone)]
pub struct SessionHandle {
    peer_id: Vec<u8>,
    session: Arc<RwLock<DoubleRatchetSession>>,
}

impl SessionHandle {
    /// Get the peer ID
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Get the session
    pub fn session(&self) -> Arc<RwLock<DoubleRatchetSession>> {
        self.session.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.enable_forward_secrecy);
        assert!(config.enable_group_messaging);
        assert_eq!(config.max_group_size, 256);
    }

    #[test]
    fn test_context_creation() {
        let config = Config::default();
        let result = SecureContext::new(config, Some(b"test_password"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_identity_generation() {
        let config = Config::default();
        let mut ctx = SecureContext::new(config, Some(b"test")).unwrap();
        let identity = ctx.generate_identity();
        assert!(identity.is_ok());
    }
}
