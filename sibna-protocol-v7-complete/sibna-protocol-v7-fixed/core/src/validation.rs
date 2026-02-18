//! Input Validation and Sanitization
//!
//! Comprehensive input validation for all external-facing APIs.
//! Prevents injection attacks, buffer overflows, and malformed data.

use std::convert::TryFrom;

/// Maximum sizes for various inputs
pub mod limits {
    /// Maximum message size (10 MB)
    pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
    /// Maximum session ID length
    pub const MAX_SESSION_ID_LEN: usize = 256;
    /// Maximum group ID length
    pub const MAX_GROUP_ID_LEN: usize = 64;
    /// Maximum associated data length
    pub const MAX_AD_LEN: usize = 1024;
    /// Maximum key size
    pub const MAX_KEY_SIZE: usize = 32;
    /// Maximum signature size
    pub const MAX_SIGNATURE_SIZE: usize = 64;
    /// Maximum password length
    pub const MAX_PASSWORD_LEN: usize = 256;
    /// Minimum password length
    pub const MIN_PASSWORD_LEN: usize = 8;
    /// Maximum metadata size
    pub const MAX_METADATA_SIZE: usize = 4096;
}

/// Validation error types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Input is too short
    TooShort { min: usize, actual: usize },
    /// Input is too long
    TooLong { max: usize, actual: usize },
    /// Input has invalid length
    InvalidLength { expected: usize, actual: usize },
    /// Input contains invalid bytes
    InvalidBytes { reason: String },
    /// Input is empty
    Empty,
    /// Input contains null bytes
    NullByte,
    /// Input failed cryptographic validation
    CryptoValidation { reason: String },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "Input too short: expected at least {} bytes, got {}", min, actual)
            }
            Self::TooLong { max, actual } => {
                write!(f, "Input too long: expected at most {} bytes, got {}", max, actual)
            }
            Self::InvalidLength { expected, actual } => {
                write!(f, "Invalid length: expected {} bytes, got {}", expected, actual)
            }
            Self::InvalidBytes { reason } => {
                write!(f, "Invalid bytes: {}", reason)
            }
            Self::Empty => write!(f, "Input is empty"),
            Self::NullByte => write!(f, "Input contains null byte"),
            Self::CryptoValidation { reason } => {
                write!(f, "Cryptographic validation failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validation result type
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validate a message (plaintext or ciphertext)
pub fn validate_message(data: &[u8]) -> ValidationResult<()> {
    if data.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if data.len() > limits::MAX_MESSAGE_SIZE {
        return Err(ValidationError::TooLong {
            max: limits::MAX_MESSAGE_SIZE,
            actual: data.len(),
        });
    }
    
    Ok(())
}

/// Validate a session ID
pub fn validate_session_id(id: &[u8]) -> ValidationResult<()> {
    if id.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if id.len() > limits::MAX_SESSION_ID_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_SESSION_ID_LEN,
            actual: id.len(),
        });
    }
    
    // Check for null bytes
    if id.contains(&0) {
        return Err(ValidationError::NullByte);
    }
    
    Ok(())
}

/// Validate a key (should be exactly 32 bytes)
pub fn validate_key(key: &[u8]) -> ValidationResult<()> {
    if key.len() != limits::MAX_KEY_SIZE {
        return Err(ValidationError::InvalidLength {
            expected: limits::MAX_KEY_SIZE,
            actual: key.len(),
        });
    }
    
    // Check that key is not all zeros (weak key)
    if key.iter().all(|&b| b == 0) {
        return Err(ValidationError::InvalidBytes {
            reason: "Key is all zeros (weak key)".to_string(),
        });
    }
    
    Ok(())
}

/// Validate a signature (should be exactly 64 bytes for Ed25519)
pub fn validate_signature(sig: &[u8]) -> ValidationResult<()> {
    if sig.len() != limits::MAX_SIGNATURE_SIZE {
        return Err(ValidationError::InvalidLength {
            expected: limits::MAX_SIGNATURE_SIZE,
            actual: sig.len(),
        });
    }
    
    Ok(())
}

/// Validate associated data
pub fn validate_associated_data(ad: &[u8]) -> ValidationResult<()> {
    if ad.len() > limits::MAX_AD_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_AD_LEN,
            actual: ad.len(),
        });
    }
    
    Ok(())
}

/// Validate a password
pub fn validate_password(password: &[u8]) -> ValidationResult<()> {
    if password.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if password.len() < limits::MIN_PASSWORD_LEN {
        return Err(ValidationError::TooShort {
            min: limits::MIN_PASSWORD_LEN,
            actual: password.len(),
        });
    }
    
    if password.len() > limits::MAX_PASSWORD_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_PASSWORD_LEN,
            actual: password.len(),
        });
    }
    
    // Check for null bytes
    if password.contains(&0) {
        return Err(ValidationError::NullByte);
    }
    
    Ok(())
}

/// Validate a ciphertext
pub fn validate_ciphertext(ciphertext: &[u8]) -> ValidationResult<()> {
    // Minimum: nonce (12) + tag (16) + at least 1 byte
    const MIN_CIPHERTEXT_LEN: usize = 29;
    
    if ciphertext.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(ValidationError::TooShort {
            min: MIN_CIPHERTEXT_LEN,
            actual: ciphertext.len(),
        });
    }
    
    if ciphertext.len() > limits::MAX_MESSAGE_SIZE {
        return Err(ValidationError::TooLong {
            max: limits::MAX_MESSAGE_SIZE,
            actual: ciphertext.len(),
        });
    }
    
    Ok(())
}

/// Validate a group ID
pub fn validate_group_id(id: &[u8]) -> ValidationResult<()> {
    if id.is_empty() {
        return Err(ValidationError::Empty);
    }
    
    if id.len() > limits::MAX_GROUP_ID_LEN {
        return Err(ValidationError::TooLong {
            max: limits::MAX_GROUP_ID_LEN,
            actual: id.len(),
        });
    }
    
    Ok(())
}

/// Validate message number (prevent overflow)
pub fn validate_message_number(n: u64) -> ValidationResult<()> {
    // Maximum reasonable message number
    const MAX_MESSAGE_NUMBER: u64 = 1_000_000_000_000;
    
    if n > MAX_MESSAGE_NUMBER {
        return Err(ValidationError::InvalidBytes {
            reason: format!("Message number {} exceeds maximum {}", n, MAX_MESSAGE_NUMBER),
        });
    }
    
    Ok(())
}

/// Validate metadata
pub fn validate_metadata(metadata: &[u8]) -> ValidationResult<()> {
    if metadata.len() > limits::MAX_METADATA_SIZE {
        return Err(ValidationError::TooLong {
            max: limits::MAX_METADATA_SIZE,
            actual: metadata.len(),
        });
    }
    
    // Check for potentially dangerous bytes
    // (this is context-dependent, adjust as needed)
    
    Ok(())
}

/// Sanitize a string input (remove control characters)
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Validate a prekey bundle
pub fn validate_prekey_bundle(
    identity_key: &[u8],
    signed_prekey: &[u8],
    signature: &[u8],
    onetime_prekey: Option<&[u8]>,
) -> ValidationResult<()> {
    validate_key(identity_key)?;
    validate_key(signed_prekey)?;
    validate_signature(signature)?;
    
    if let Some(opk) = onetime_prekey {
        validate_key(opk)?;
    }
    
    Ok(())
}

/// Validate handshake output
pub fn validate_handshake_output(
    shared_secret: &[u8],
    ephemeral_key: &[u8],
) -> ValidationResult<()> {
    // Shared secret should be 32 bytes
    if shared_secret.len() != 32 {
        return Err(ValidationError::InvalidLength {
            expected: 32,
            actual: shared_secret.len(),
        });
    }
    
    // Ephemeral key should be 32 bytes
    if ephemeral_key.len() != 32 {
        return Err(ValidationError::InvalidLength {
            expected: 32,
            actual: ephemeral_key.len(),
        });
    }
    
    // Check shared secret is not all zeros
    if shared_secret.iter().all(|&b| b == 0) {
        return Err(ValidationError::CryptoValidation {
            reason: "Shared secret is all zeros - possible DH failure".to_string(),
        });
    }
    
    Ok(())
}

/// Constant-time byte comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_key() {
        // Valid key
        assert!(validate_key(&[1u8; 32]).is_ok());
        
        // Wrong length
        assert!(validate_key(&[1u8; 16]).is_err());
        
        // All zeros (weak)
        assert!(validate_key(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_validate_message() {
        // Valid message
        assert!(validate_message(b"hello").is_ok());
        
        // Empty
        assert!(validate_message(b"").is_err());
        
        // Too large
        let large = vec![0u8; limits::MAX_MESSAGE_SIZE + 1];
        assert!(validate_message(&large).is_err());
    }

    #[test]
    fn test_validate_password() {
        // Valid password
        assert!(validate_password(b"password123").is_ok());
        
        // Too short
        assert!(validate_password(b"short").is_err());
        
        // Contains null
        assert!(validate_password(b"pass\x00word").is_err());
    }

    #[test]
    fn test_validate_ciphertext() {
        // Too short
        assert!(validate_ciphertext(&[0u8; 20]).is_err());
        
        // Valid (minimum)
        assert!(validate_ciphertext(&[0u8; 29]).is_ok());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[]));
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("hello"), "hello");
        assert_eq!(sanitize_string("hello\x00world"), "helloworld");
        assert_eq!(sanitize_string("hello\nworld"), "hello\nworld");
    }
}
