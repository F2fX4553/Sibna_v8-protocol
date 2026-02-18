//! Error types for the Sibna Protocol
//!
//! This module defines all error types used throughout the protocol.

use thiserror::Error;

/// Protocol Error Type
///
/// Comprehensive error enumeration for all protocol operations.
#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    /// Invalid key length
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLengthWithDetails {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Invalid key length (simple)
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Authentication failed
    #[error("Authentication failed: message may be corrupted or tampered")]
    AuthenticationFailed,

    /// Invalid nonce
    #[error("Invalid nonce")]
    InvalidNonce,

    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound,

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Key derivation failed
    #[error("Key derivation failed")]
    KeyDerivationFailed,

    /// Invalid message
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Out of memory
    #[error("Out of memory")]
    OutOfMemory,

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    /// Invalid nonce length
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Random generation failed
    #[error("Random generation failed")]
    RandomFailed,

    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Invalid argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Maximum skipped messages exceeded
    #[error("Maximum skipped messages exceeded")]
    MaxSkippedMessagesExceeded,

    /// Replay attack detected
    #[error("Replay attack detected")]
    ReplayAttackDetected,
}

/// Result type for protocol operations
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<crate::crypto::CryptoError> for ProtocolError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        match err {
            crate::crypto::CryptoError::InvalidKeyLength => ProtocolError::InvalidKeyLength,
            crate::crypto::CryptoError::EncryptionFailed(msg) => ProtocolError::EncryptionFailed(msg),
            crate::crypto::CryptoError::DecryptionFailed(msg) => ProtocolError::DecryptionFailed(msg),
            crate::crypto::CryptoError::AuthenticationFailed => ProtocolError::AuthenticationFailed,
            crate::crypto::CryptoError::InvalidNonceLength { expected, actual } => {
                ProtocolError::InvalidNonceLength { expected, actual }
            }
            crate::crypto::CryptoError::RandomFailed => ProtocolError::RandomFailed,
            crate::crypto::CryptoError::KeyDerivationFailed => ProtocolError::KeyDerivationFailed,
            crate::crypto::CryptoError::InvalidCiphertext => ProtocolError::InvalidCiphertext,
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(err: std::io::Error) -> Self {
        ProtocolError::InternalError(err.to_string())
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(err: serde_json::Error) -> Self {
        ProtocolError::SerializationError(err.to_string())
    }
}
