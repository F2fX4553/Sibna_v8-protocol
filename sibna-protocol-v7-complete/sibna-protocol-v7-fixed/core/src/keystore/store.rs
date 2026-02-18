//! Secure Key Store Implementation
//!
//! Provides encrypted persistent storage for cryptographic keys.

use super::*;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::OsRng;
use parking_lot::RwLock;
use sled;
use std::sync::Arc;

/// Identity Key Pair (Dual Ed25519/X25519)
///
/// Supports both signing (Ed25519) and key agreement (X25519).
#[derive(Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// Private key seed (32 bytes)
    #[serde(with = "serde_bytes")]
    pub private_seed: Vec<u8>,
    /// Ed25519 public key for signatures
    #[serde(with = "serde_bytes")]
    pub ed25519_public: Vec<u8>,
    /// X25519 public key for key agreement
    #[serde(with = "serde_bytes")]
    pub x25519_public: Vec<u8>,
}

impl Zeroize for IdentityKeyPair {
    fn zeroize(&mut self) {
        self.private_seed.zeroize();
    }
}

impl ZeroizeOnDrop for IdentityKeyPair {}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);

        let signing_key = SigningKey::from_bytes(&seed);
        let ed_public = VerifyingKey::from(&signing_key);

        let x_secret = StaticSecret::from(seed);
        let x_public = PublicKey::from(&x_secret);

        Self {
            private_seed: seed.to_vec(),
            ed25519_public: ed_public.to_bytes().to_vec(),
            x25519_public: x_public.as_bytes().to_vec(),
        }
    }

    /// Create from existing bytes
    ///
    /// # Arguments
    /// * `public_ed` - Ed25519 public key (32 bytes)
    /// * `public_x` - X25519 public key (32 bytes)
    /// * `seed` - Private key seed (32 bytes)
    pub fn from_bytes(public_ed: &[u8], public_x: &[u8], seed: &[u8]) -> Self {
        Self {
            private_seed: seed.to_vec(),
            ed25519_public: public_ed.to_vec(),
            x25519_public: public_x.to_vec(),
        }
    }

    /// Sign a message with Ed25519
    ///
    /// # Arguments
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// 64-byte signature
    pub fn sign(&self, message: &[u8]) -> crate::error::ProtocolResult<Vec<u8>> {
        if self.private_seed.len() != 32 {
            return Err(crate::error::ProtocolError::InvalidKeyLength);
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.private_seed);

        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(message);

        Ok(signature.to_bytes().to_vec())
    }

    /// Get X25519 secret key for key agreement
    pub fn get_x25519_secret(&self) -> StaticSecret {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.private_seed);
        StaticSecret::from(seed)
    }

    /// Verify a signature
    ///
    /// # Arguments
    /// * `message` - Original message
    /// * `signature` - Signature to verify
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if self.ed25519_public.len() != 32 || signature.len() != 64 {
            return false;
        }

        let Ok(public_key) = VerifyingKey::try_from(
            <[u8; 32]>::try_from(&self.ed25519_public[..]).unwrap()
        ) else {
            return false;
        };

        let Ok(sig) = ed25519_dalek::Signature::try_from(signature) else {
            return false;
        };

        public_key.verify(message, &sig).is_ok()
    }
}

/// Custom serialization for bytes
mod serde_bytes {
    use serde::{Serializer, Deserializer};

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

/// One-Time PreKey Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreKeyPair {
    /// Private key
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    /// Public key
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
}

impl PreKeyPair {
    /// Generate a new prekey pair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);

        Self {
            private: secret.to_bytes().to_vec(),
            public: public.as_bytes().to_vec(),
        }
    }
}

/// Signed PreKey Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKeyPair {
    /// Private key
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    /// Public key
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    /// Ed25519 signature of public key
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedPreKeyPair {
    /// Generate a signed prekey pair
    ///
    /// # Arguments
    /// * `identity` - Identity key pair for signing
    pub fn generate_signed(identity: &IdentityKeyPair) -> crate::error::ProtocolResult<Self> {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        let public_bytes = public.as_bytes();

        let signature = identity.sign(public_bytes)?;

        Ok(Self {
            private: secret.to_bytes().to_vec(),
            public: public_bytes.to_vec(),
            signature,
        })
    }

    /// Verify the signature
    pub fn verify_signature(&self, identity: &IdentityKeyPair) -> bool {
        identity.verify(&self.public, &self.signature)
    }
}

/// Secure Key Store
///
/// Provides encrypted persistent storage for all key types.
pub struct KeyStore {
    identity_key: RwLock<Option<IdentityKeyPair>>,
    db: Option<sled::Tree>,
    crypto: crate::crypto::CryptoHandler,
    // In-memory storage for WASM
    memory_store: RwLock<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
}

impl KeyStore {
    /// Create a new keystore
    ///
    /// # Arguments
    /// * `db` - Sled database instance
    /// * `storage_key` - 32-byte encryption key
    pub fn new(db: Arc<sled::Db>, storage_key: [u8; 32]) -> crate::error::ProtocolResult<Self> {
        let tree = db.open_tree("keystore")
            .map_err(|e| crate::error::ProtocolError::StorageError(e.to_string()))?;

        let crypto = crate::crypto::CryptoHandler::new(&storage_key)
            .map_err(crate::error::ProtocolError::from)?;

        // Try to load existing identity
        let mut identity_key = None;
        if let Ok(Some(encrypted)) = tree.get(b"identity") {
            if let Ok(decrypted) = crypto.decrypt(&encrypted, b"keystore:identity") {
                if let Ok(loaded) = serde_json::from_slice::<IdentityKeyPair>(&decrypted) {
                    identity_key = Some(loaded);
                }
            }
        }

        // Generate new identity if none exists
        if identity_key.is_none() {
            let identity = IdentityKeyPair::generate();
            let bytes = serde_json::to_vec(&identity)
                .map_err(|e| crate::error::ProtocolError::SerializationError(e.to_string()))?;
            let encrypted = crypto.encrypt(&bytes, b"keystore:identity")
                .map_err(crate::error::ProtocolError::from)?;
            tree.insert(b"identity", encrypted)
                .map_err(|e| crate::error::ProtocolError::StorageError(e.to_string()))?;
            identity_key = Some(identity);
        }

        Ok(Self {
            identity_key: RwLock::new(identity_key),
            db: Some(tree),
            crypto,
            memory_store: RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Create an in-memory keystore (for WASM/testing)
    #[cfg(target_arch = "wasm32")]
    pub fn new_in_memory() -> crate::error::ProtocolResult<Self> {
        let storage_key = [0u8; 32];
        let crypto = crate::crypto::CryptoHandler::new(&storage_key)?;

        // Generate identity
        let identity = IdentityKeyPair::generate();

        Ok(Self {
            identity_key: RwLock::new(Some(identity)),
            db: None,
            crypto,
            memory_store: RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Store a value
    fn store(&self, key: &[u8], value: Vec<u8>) -> crate::error::ProtocolResult<()> {
        if let Some(ref db) = self.db {
            db.insert(key, value.clone())
                .map_err(|e| crate::error::ProtocolError::StorageError(e.to_string()))?;
        } else {
            self.memory_store.write().insert(key.to_vec(), value);
        }
        Ok(())
    }

    /// Load a value
    fn load(&self, key: &[u8]) -> crate::error::ProtocolResult<Option<Vec<u8>>> {
        if let Some(ref db) = self.db {
            db.get(key)
                .map(|v| v.map(|ivec| ivec.to_vec()))
                .map_err(|e| crate::error::ProtocolError::StorageError(e.to_string()))
        } else {
            Ok(self.memory_store.read().get(key).cloned())
        }
    }

    /// Set the identity key pair
    pub fn set_identity(&self, identity: IdentityKeyPair) -> crate::error::ProtocolResult<()> {
        let bytes = serde_json::to_vec(&identity)
            .map_err(|e| crate::error::ProtocolError::SerializationError(e.to_string()))?;

        let encrypted = self.crypto.encrypt(&bytes, b"keystore:identity")
            .map_err(crate::error::ProtocolError::from)?;

        self.store(b"identity", encrypted)?;

        let mut guard = self.identity_key.write();
        *guard = Some(identity);

        Ok(())
    }

    /// Get the identity key pair
    pub fn get_identity_keypair(&self) -> crate::error::ProtocolResult<IdentityKeyPair> {
        let guard = self.identity_key.read();

        match &*guard {
            Some(key) => Ok(IdentityKeyPair {
                private_seed: key.private_seed.clone(),
                ed25519_public: key.ed25519_public.clone(),
                x25519_public: key.x25519_public.clone(),
            }),
            None => Err(crate::error::ProtocolError::KeyNotFound("identity".to_string())),
        }
    }

    /// Save a one-time prekey
    pub fn save_prekey(&self, id: u32, keypair: &PreKeyPair) -> crate::error::ProtocolResult<()> {
        let bytes = serde_json::to_vec(keypair)
            .map_err(|e| crate::error::ProtocolError::SerializationError(e.to_string()))?;

        let ad = format!("keystore:prekey:{}", id);
        let encrypted = self.crypto.encrypt(&bytes, ad.as_bytes())
            .map_err(crate::error::ProtocolError::from)?;

        let key = format!("prekey:{}", id);
        self.store(key.as_bytes(), encrypted)?;

        Ok(())
    }

    /// Get a one-time prekey
    pub fn get_prekey(&self, id: u32) -> crate::error::ProtocolResult<PreKeyPair> {
        let key = format!("prekey:{}", id);
        let ad = format!("keystore:prekey:{}", id);

        match self.load(key.as_bytes())? {
            Some(encrypted) => {
                let decrypted = self.crypto.decrypt(&encrypted, ad.as_bytes())
                    .map_err(crate::error::ProtocolError::from)?;

                serde_json::from_slice(&decrypted)
                    .map_err(|e| crate::error::ProtocolError::DeserializationError(e.to_string()))
            }
            None => Err(crate::error::ProtocolError::KeyNotFound(format!("prekey:{}", id))),
        }
    }

    /// Remove a one-time prekey
    pub fn remove_prekey(&self, id: u32) -> crate::error::ProtocolResult<()> {
        let key = format!("prekey:{}", id);
        if let Some(ref db) = self.db {
            db.remove(key.as_bytes())
                .map_err(|e| crate::error::ProtocolError::StorageError(e.to_string()))?;
        } else {
            self.memory_store.write().remove(key.as_bytes());
        }
        Ok(())
    }

    /// Save a signed prekey
    pub fn save_signed_prekey(&self, id: u32, keypair: &SignedPreKeyPair) -> crate::error::ProtocolResult<()> {
        let bytes = serde_json::to_vec(keypair)
            .map_err(|e| crate::error::ProtocolError::SerializationError(e.to_string()))?;

        let ad = format!("keystore:signed_prekey:{}", id);
        let encrypted = self.crypto.encrypt(&bytes, ad.as_bytes())
            .map_err(crate::error::ProtocolError::from)?;

        let key = format!("signed_prekey:{}", id);
        self.store(key.as_bytes(), encrypted)?;

        Ok(())
    }

    /// Get a signed prekey
    pub fn get_signed_prekey(&self, id: u32) -> crate::error::ProtocolResult<SignedPreKeyPair> {
        let key = format!("signed_prekey:{}", id);
        let ad = format!("keystore:signed_prekey:{}", id);

        match self.load(key.as_bytes())? {
            Some(encrypted) => {
                let decrypted = self.crypto.decrypt(&encrypted, ad.as_bytes())
                    .map_err(crate::error::ProtocolError::from)?;

                serde_json::from_slice(&decrypted)
                    .map_err(|e| crate::error::ProtocolError::DeserializationError(e.to_string()))
            }
            None => Err(crate::error::ProtocolError::KeyNotFound(format!("signed_prekey:{}", id))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_identity_generation() {
        let id1 = IdentityKeyPair::generate();
        let id2 = IdentityKeyPair::generate();

        // Keys should be different
        assert_ne!(id1.private_seed, id2.private_seed);
        assert_ne!(id1.x25519_public, id2.x25519_public);
    }

    #[test]
    fn test_signing() {
        let identity = IdentityKeyPair::generate();
        let message = b"Test message";

        let signature = identity.sign(message).unwrap();
        assert!(identity.verify(message, &signature));
    }

    #[test]
    fn test_keystore() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let ks = KeyStore::new(Arc::new(db), [0x42u8; 32]).unwrap();

        // Should have auto-generated identity
        let identity = ks.get_identity_keypair();
        assert!(identity.is_ok());
    }

    #[test]
    fn test_prekey_storage() {
        let dir = tempdir().unwrap();
        let db = sled::open(dir.path()).unwrap();

        let ks = KeyStore::new(Arc::new(db), [0x42u8; 32]).unwrap();

        let prekey = PreKeyPair::generate();
        ks.save_prekey(1, &prekey).unwrap();

        let loaded = ks.get_prekey(1).unwrap();
        assert_eq!(prekey.public, loaded.public);
    }
}
