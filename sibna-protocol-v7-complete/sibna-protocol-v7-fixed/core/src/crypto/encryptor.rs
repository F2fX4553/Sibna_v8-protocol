//! Message Encryptor
//!
//! Provides message encryption with automatic counter management.

use std::sync::atomic::{AtomicU64, Ordering};
use super::{CryptoHandler, CryptoError, CryptoResult, NONCE_LENGTH};

/// Encryptor with message counter tracking
///
/// Provides message encryption with automatic key rotation
/// after a configurable number of messages.
pub struct Encryptor {
    handler: CryptoHandler,
    message_counter: AtomicU64,
    max_message_count: u64,
}

impl Encryptor {
    /// Create a new encryptor
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `max_message_count` - Maximum messages before key rotation required
    ///
    /// # Errors
    /// Returns error if key length is invalid
    pub fn new(key: &[u8], max_message_count: u64) -> CryptoResult<Self> {
        let handler = CryptoHandler::new(key)?;

        Ok(Self {
            handler,
            message_counter: AtomicU64::new(0),
            max_message_count,
        })
    }

    /// Encrypt a message
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `context` - Context information for associated data
    ///
    /// # Returns
    /// The encrypted message with counter and timestamp
    pub fn encrypt_message(&self, plaintext: &[u8], context: &[u8]) -> CryptoResult<Vec<u8>> {
        let message_num = self.message_counter.fetch_add(1, Ordering::SeqCst);

        // Check if we've exceeded max messages (key rotation needed)
        if message_num >= self.max_message_count {
            return Err(CryptoError::EncryptionFailed(
                "Maximum message count exceeded, key rotation required".to_string()
            ));
        }

        // Build associated data: context || message_number || timestamp
        let mut associated_data = Vec::with_capacity(context.len() + 16);
        associated_data.extend_from_slice(context);
        associated_data.extend_from_slice(&message_num.to_le_bytes());

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CryptoError::EncryptionFailed("System time error".to_string()))?
            .as_secs();
        associated_data.extend_from_slice(&timestamp.to_le_bytes());

        self.handler.encrypt(plaintext, &associated_data)
    }

    /// Decrypt a message
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data
    /// * `context` - Context information (must match encryption)
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt_message(&self, ciphertext: &[u8], context: &[u8]) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < NONCE_LENGTH {
            return Err(CryptoError::InvalidCiphertext);
        }

        self.handler.decrypt(ciphertext, context)
    }

    /// Get current message count
    pub fn message_count(&self) -> u64 {
        self.message_counter.load(Ordering::SeqCst)
    }

    /// Reset the message counter
    ///
    /// # Security Note
    /// This should only be called after key rotation
    pub fn reset_counter(&self) {
        self.message_counter.store(0, Ordering::SeqCst);
    }

    /// Check if key rotation is needed
    pub fn needs_rotation(&self) -> bool {
        self.message_count() >= self.max_message_count
    }

    /// Get remaining messages until rotation
    pub fn remaining_messages(&self) -> u64 {
        self.max_message_count.saturating_sub(self.message_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryptor_roundtrip() {
        let key = [0x42u8; 32];
        let encryptor = Encryptor::new(&key, 1000).unwrap();

        let plaintext = b"Secret message";
        let context = b"session_123";

        let ciphertext = encryptor.encrypt_message(plaintext, context).unwrap();
        let decrypted = encryptor.decrypt_message(&ciphertext, context).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_message_counter() {
        let key = [0x42u8; 32];
        let encryptor = Encryptor::new(&key, 5).unwrap();

        assert_eq!(encryptor.message_count(), 0);
        assert!(!encryptor.needs_rotation());

        // Send 5 messages
        for _ in 0..5 {
            encryptor.encrypt_message(b"test", b"ctx").unwrap();
        }

        assert_eq!(encryptor.message_count(), 5);
        assert!(encryptor.needs_rotation());

        // Next should fail
        let result = encryptor.encrypt_message(b"test", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_reset() {
        let key = [0x42u8; 32];
        let encryptor = Encryptor::new(&key, 100).unwrap();

        encryptor.encrypt_message(b"test", b"ctx").unwrap();
        assert_eq!(encryptor.message_count(), 1);

        encryptor.reset_counter();
        assert_eq!(encryptor.message_count(), 0);
    }
}
