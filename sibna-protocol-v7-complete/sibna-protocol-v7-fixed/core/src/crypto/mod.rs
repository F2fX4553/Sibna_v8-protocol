//! Secure Crypto Module
//!
//! Safe implementation of cryptographic algorithms using well-audited libraries.
//! This module provides:
//! - ChaCha20-Poly1305 AEAD encryption
//! - HKDF key derivation
//! - Secure random number generation

pub mod encryptor;
pub mod random;
pub mod kdf;

pub use encryptor::*;
pub use random::*;
pub use kdf::*;

use zeroize::Zeroizing;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, AeadInPlace},
};
use thiserror::Error;

/// Crypto Errors
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Authentication failed
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Random generation failed
    #[error("Random generation failed")]
    RandomFailed,

    /// Key derivation failed
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

/// Result type for crypto operations
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

/// Key length in bytes (256 bits)
pub const KEY_LENGTH: usize = 32;

/// Nonce length in bytes (96 bits)
pub const NONCE_LENGTH: usize = 12;

/// Authentication tag length in bytes (128 bits)
pub const TAG_LENGTH: usize = 16;

/// ChaCha20 nonce length
pub const CHACHA20_NONCE_LENGTH: usize = 12;

/// General Encryption Handler
///
/// Provides authenticated encryption using ChaCha20-Poly1305.
/// All operations are constant-time where possible.
pub struct CryptoHandler {
    cipher: ChaCha20Poly1305,
    key: Zeroizing<[u8; KEY_LENGTH]>,
}

impl CryptoHandler {
    /// Create a new crypto handler with the given key
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidKeyLength` if key is not 32 bytes
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        if key.len() != KEY_LENGTH {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut key_array = [0u8; KEY_LENGTH];
        key_array.copy_from_slice(key);

        let cipher = ChaCha20Poly1305::new(&key_array.into());

        Ok(Self {
            cipher,
            key: Zeroizing::new(key_array),
        })
    }

    /// Encrypt data with automatic nonce generation
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// nonce || ciphertext || tag
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut rng = SecureRandom::new()?;
        let mut nonce = [0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);

        self.encrypt_with_nonce(plaintext, associated_data, &nonce)
    }

    /// Encrypt with a specific nonce
    ///
    /// # Security Warning
    /// Never reuse a nonce with the same key!
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data
    /// * `nonce` - 12-byte nonce
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce.len() != NONCE_LENGTH {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LENGTH,
                actual: nonce.len(),
            });
        }

        let ciphertext = self.cipher
            .encrypt(nonce.into(), chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            })
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Result: nonce || ciphertext (which includes tag)
        let mut result = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    ///
    /// # Arguments
    /// * `ciphertext` - nonce || ciphertext || tag
    /// * `associated_data` - Additional authenticated data
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce = &ciphertext[..NONCE_LENGTH];
        let encrypted_data = &ciphertext[NONCE_LENGTH..];

        self.cipher
            .decrypt(nonce.into(), chacha20poly1305::aead::Payload {
                msg: encrypted_data,
                aad: associated_data,
            })
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Get the key length
    pub fn key_len(&self) -> usize {
        KEY_LENGTH
    }
}

/// Zeroize the key on drop
impl Drop for CryptoHandler {
    fn drop(&mut self) {
        // Zeroizing is handled automatically by Zeroizing wrapper
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = [0x42u8; 32];
        let handler = CryptoHandler::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = handler.encrypt(plaintext, ad).unwrap();
        let decrypted = handler.decrypt(&ciphertext, ad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0x42u8; 32];
        let handler = CryptoHandler::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ad = b"associated data";

        let ciphertext = handler.encrypt(plaintext, ad).unwrap();
        let result = handler.decrypt(&ciphertext, b"wrong ad");

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x42u8; 16]; // Wrong length
        let result = CryptoHandler::new(&key);
        assert!(result.is_err());
    }
}
