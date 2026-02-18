//! X3DH Handshake Builder
//!
//! Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.

use crate::Config;
use crate::keystore::{KeyStore, IdentityKeyPair};
use crate::crypto::SecureRandom;
use crate::error::{ProtocolResult, ProtocolError};
use x25519_dalek::{StaticSecret, PublicKey};
use rand_core::OsRng;

/// Handshake Builder
///
/// Provides a fluent interface for configuring X3DH handshakes.
pub struct HandshakeBuilder<'a> {
    config: Option<Config>,
    keystore: Option<&'a KeyStore>,
    random: Option<&'a SecureRandom>,
    initiator: bool,
    peer_identity_key: Option<PublicKey>,
    peer_signed_prekey: Option<PublicKey>,
    peer_onetime_prekey: Option<PublicKey>,
    prologue: Vec<u8>,
}

impl<'a> HandshakeBuilder<'a> {
    /// Create a new handshake builder
    pub fn new() -> Self {
        Self {
            config: None,
            keystore: None,
            random: None,
            initiator: false,
            peer_identity_key: None,
            peer_signed_prekey: None,
            peer_onetime_prekey: None,
            prologue: Vec::new(),
        }
    }

    /// Set configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set keystore reference
    pub fn with_keystore(mut self, keystore: &'a KeyStore) -> Self {
        self.keystore = Some(keystore);
        self
    }

    /// Set random generator
    pub fn with_random(mut self, random: &'a SecureRandom) -> Self {
        self.random = Some(random);
        self
    }

    /// Set initiator flag
    pub fn with_initiator(mut self, initiator: bool) -> Self {
        self.initiator = initiator;
        self
    }

    /// Set peer's identity public key
    ///
    /// # Arguments
    /// * `key` - 32-byte X25519 public key
    pub fn with_peer_identity_key(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }

        let k: [u8; 32] = key.try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;

        self.peer_identity_key = Some(PublicKey::from(k));
        Ok(self)
    }

    /// Set peer's signed prekey
    ///
    /// # Arguments
    /// * `key` - 32-byte X25519 public key
    pub fn with_peer_signed_prekey(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }

        let k: [u8; 32] = key.try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;

        self.peer_signed_prekey = Some(PublicKey::from(k));
        Ok(self)
    }

    /// Set peer's one-time prekey
    ///
    /// # Arguments
    /// * `key` - 32-byte X25519 public key
    pub fn with_peer_onetime_prekey(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 {
            return Err(ProtocolError::InvalidKeyLength);
        }

        let k: [u8; 32] = key.try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength)?;

        self.peer_onetime_prekey = Some(PublicKey::from(k));
        Ok(self)
    }

    /// Set prologue data for binding
    pub fn with_prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = prologue.to_vec();
        self
    }

    /// Build the handshake
    ///
    /// # Errors
    /// Returns error if required fields are missing
    pub fn build(self) -> ProtocolResult<Handshake> {
        let keystore = self.keystore.ok_or_else(|| {
            ProtocolError::InvalidState("Keystore is required".to_string())
        })?;

        let identity_key = keystore.get_identity_keypair()?;
        let ephemeral_key = StaticSecret::random_from_rng(&mut OsRng);

        Ok(Handshake {
            config: self.config.ok_or_else(|| {
                ProtocolError::InvalidState("Config is required".to_string())
            })?,
            initiator: self.initiator,
            identity_key,
            ephemeral_key,
            peer_identity_key: self.peer_identity_key,
            peer_signed_prekey: self.peer_signed_prekey,
            peer_onetime_prekey: self.peer_onetime_prekey,
            prologue: self.prologue,
        })
    }
}

impl<'a> Default for HandshakeBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// X3DH Handshake
///
/// Performs the X3DH key agreement protocol.
pub struct Handshake {
    config: Config,
    initiator: bool,
    prologue: Vec<u8>,
    identity_key: IdentityKeyPair,
    ephemeral_key: StaticSecret,
    peer_identity_key: Option<PublicKey>,
    peer_signed_prekey: Option<PublicKey>,
    peer_onetime_prekey: Option<PublicKey>,
}

/// Handshake Output
///
/// Contains the results of a successful handshake.
pub struct HandshakeOutput {
    /// Shared secret (32 bytes)
    pub shared_secret: [u8; 32],
    /// Local ephemeral key for session initialization
    pub local_ephemeral_key: StaticSecret,
}

impl Handshake {
    /// Perform the handshake
    ///
    /// # Returns
    /// The shared secret and local ephemeral key
    pub fn perform(&self) -> ProtocolResult<HandshakeOutput> {
        if self.initiator {
            self.perform_initiator()
        } else {
            self.perform_responder()
        }
    }

    /// Perform initiator side of X3DH
    fn perform_initiator(&self) -> ProtocolResult<HandshakeOutput> {
        let peer_ik = self.peer_identity_key.as_ref()
            .ok_or_else(|| ProtocolError::InvalidState("Peer identity key required".to_string()))?;
        let peer_spk = self.peer_signed_prekey.as_ref()
            .ok_or_else(|| ProtocolError::InvalidState("Peer signed prekey required".to_string()))?;

        let ik_a = self.identity_key.get_x25519_secret();
        let ek_a = &self.ephemeral_key;

        // X3DH calculations:
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = ik_a.diffie_hellman(peer_spk);
        // DH2 = DH(EK_A, IK_B)
        let dh2 = ek_a.diffie_hellman(peer_ik);
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ek_a.diffie_hellman(peer_spk);

        // Combine DH outputs
        let mut dh_material = Vec::with_capacity(32 * 4);
        dh_material.extend_from_slice(dh1.as_bytes());
        dh_material.extend_from_slice(dh2.as_bytes());
        dh_material.extend_from_slice(dh3.as_bytes());

        // Optional: DH4 with one-time prekey
        if let Some(peer_opk) = &self.peer_onetime_prekey {
            let dh4 = ek_a.diffie_hellman(peer_opk);
            dh_material.extend_from_slice(dh4.as_bytes());
        }

        // Derive shared secret
        let mut shared_secret = [0u8; 32];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &dh_material);
        hkdf.expand(b"X3DH_SS", &mut shared_secret)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        Ok(HandshakeOutput {
            shared_secret,
            local_ephemeral_key: StaticSecret::from(ek_a.to_bytes()),
        })
    }

    /// Perform responder side of X3DH
    fn perform_responder(&self) -> ProtocolResult<HandshakeOutput> {
        let peer_ik = self.peer_identity_key.as_ref()
            .ok_or_else(|| ProtocolError::InvalidState("Peer identity key required".to_string()))?;
        let peer_ek = self.peer_onetime_prekey.as_ref()
            .ok_or_else(|| ProtocolError::InvalidState("Peer ephemeral key required (as onetime_prekey)".to_string()))?;

        let ik_b = self.identity_key.get_x25519_secret();
        let spk_b = &self.ephemeral_key;

        // X3DH calculations (responder perspective):
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = spk_b.diffie_hellman(peer_ik);
        // DH2 = DH(IK_B, EK_A)
        let dh2 = ik_b.diffie_hellman(peer_ek);
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = spk_b.diffie_hellman(peer_ek);

        // Combine DH outputs
        let mut dh_material = Vec::with_capacity(32 * 4);
        dh_material.extend_from_slice(dh1.as_bytes());
        dh_material.extend_from_slice(dh2.as_bytes());
        dh_material.extend_from_slice(dh3.as_bytes());

        // Derive shared secret
        let mut shared_secret = [0u8; 32];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &dh_material);
        hkdf.expand(b"X3DH_SS", &mut shared_secret)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;

        Ok(HandshakeOutput {
            shared_secret,
            local_ephemeral_key: StaticSecret::from(spk_b.to_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::PreKeyPair;
    use tempfile::tempdir;
    use std::sync::Arc;

    #[test]
    fn test_x3dh_handshake_flow() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();

        // Setup Alice (Initiator)
        let db_a = sled::open(dir_a.path()).unwrap();
        let ks_a = KeyStore::new(Arc::new(db_a), [0u8; 32]).unwrap();
        ks_a.set_identity(IdentityKeyPair::generate()).unwrap();
        let id_a = ks_a.get_identity_keypair().unwrap();

        // Setup Bob (Responder)
        let db_b = sled::open(dir_b.path()).unwrap();
        let ks_b = KeyStore::new(Arc::new(db_b), [0u8; 32]).unwrap();
        ks_b.set_identity(IdentityKeyPair::generate()).unwrap();
        let id_b = ks_b.get_identity_keypair().unwrap();

        // Bob creates pre-keys
        let spk_b = PreKeyPair::generate();
        let opk_b = PreKeyPair::generate();

        // Alice builds handshake
        let handshake_a = HandshakeBuilder::new()
            .with_config(Config::default())
            .with_keystore(&ks_a)
            .with_initiator(true)
            .with_peer_identity_key(&id_b.x25519_public).unwrap()
            .with_peer_signed_prekey(&spk_b.public).unwrap()
            .with_peer_onetime_prekey(&opk_b.public).unwrap()
            .build().unwrap();

        let output_a = handshake_a.perform().unwrap();

        // Bob builds handshake (Responder)
        let handshake_b = HandshakeBuilder::new()
            .with_config(Config::default())
            .with_keystore(&ks_b)
            .with_initiator(false)
            .with_peer_identity_key(&id_a.x25519_public).unwrap()
            .with_peer_onetime_prekey(output_a.local_ephemeral_key.to_bytes().as_slice()).unwrap()
            .build().unwrap();

        let output_b = handshake_b.perform().unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(output_a.shared_secret, output_b.shared_secret);
    }
}
