//! Key Derivation Functions
//!
//! Provides HKDF-based key derivation for the protocol.

use hkdf::Hkdf;
use sha2::Sha256;
use super::{CryptoError, CryptoResult};

/// HKDF Expand
///
/// Derives output keying material from a pseudorandom key.
///
/// # Arguments
/// * `prk` - Pseudorandom key (must be at least 32 bytes)
/// * `info` - Context and application specific information
/// * `length` - Desired output length (max 255 * 32 = 8160 bytes)
///
/// # Returns
/// The derived key material
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    if prk.len() < 32 {
        return Err(CryptoError::KeyDerivationFailed);
    }

    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(okm)
}

/// HKDF Extract
///
/// Extracts a pseudorandom key from input keying material.
///
/// # Arguments
/// * `salt` - Optional salt value
/// * `ikm` - Input keying material
///
/// # Returns
/// A tuple of (PRK, Hkdf instance)
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> (Vec<u8>, Hkdf<Sha256>) {
    Hkdf::<Sha256>::extract(salt, ikm)
}

/// HKDF Extract and Expand
///
/// Single-step key derivation from input keying material.
///
/// # Arguments
/// * `salt` - Optional salt value
/// * `ikm` - Input keying material
/// * `info` - Context information
/// * `length` - Desired output length
///
/// # Returns
/// The derived key material
pub fn hkdf_derive(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(okm)
}

/// Derive a 256-bit key
///
/// Convenience function for deriving a single 32-byte key.
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt
/// * `context` - Context string for domain separation
pub fn derive_key_256(ikm: &[u8], salt: Option<&[u8]>, context: &[u8]) -> CryptoResult<[u8; 32]> {
    let derived = hkdf_derive(salt, ikm, context, 32)?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&derived);

    Ok(key)
}

/// Derive multiple keys from a single IKM
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt
/// * `contexts` - List of context strings for each key
///
/// # Returns
/// A vector of 32-byte keys
pub fn derive_multiple_keys(
    ikm: &[u8],
    salt: Option<&[u8]>,
    contexts: &[&[u8]],
) -> CryptoResult<Vec<[u8; 32]>> {
    let mut keys = Vec::with_capacity(contexts.len());

    for context in contexts {
        keys.push(derive_key_256(ikm, salt, context)?);
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42u8; 32];
        let info = b"test context";
        let result = hkdf_expand(&prk, info, 32);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_key() {
        let ikm = b"input key material";
        let salt = b"salt";
        let context = b"test context";

        let key = derive_key_256(ikm.as_slice(), Some(salt.as_slice()), context);
        assert!(key.is_ok());
    }

    #[test]
    fn test_different_contexts() {
        let ikm = b"input key material";

        let key1 = derive_key_256(ikm.as_slice(), None, b"context1").unwrap();
        let key2 = derive_key_256(ikm.as_slice(), None, b"context2").unwrap();

        // Different contexts should produce different keys
        assert_ne!(key1, key2);
    }
}
