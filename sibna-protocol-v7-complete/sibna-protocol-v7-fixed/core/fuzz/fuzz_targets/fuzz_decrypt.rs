//! Fuzz Testing for Sibna Protocol - Decryption
//!
//! Run with: cargo fuzz run fuzz_decrypt

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::convert::TryInto;

fuzz_target!(|data: &[u8]| {
    // Test decryption with random input
    if data.len() >= 76 {
        let _ = test_decrypt_random(data);
    }
    
    // Test key derivation with random input
    if data.len() >= 32 {
        let _ = test_key_derivation(data);
    }
});

fn test_decrypt_random(data: &[u8]) -> Result<(), ()> {
    use sibna::crypto::CryptoHandler;
    
    // Try to create handler with first 32 bytes as key
    let key: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    
    if let Ok(handler) = CryptoHandler::new(&key) {
        // Try to decrypt remaining data with various AD
        let _ = handler.decrypt(&data[32..], b"");
        let _ = handler.decrypt(&data[32..], b"test_ad");
        let _ = handler.decrypt(&data[32..], data);
    }
    
    Ok(())
}

fn test_key_derivation(data: &[u8]) -> Result<(), ()> {
    use sibna::crypto::{hkdf_expand, derive_key_256};
    
    let prk: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    
    // Test HKDF expand
    let _ = hkdf_expand(&prk, b"", 32);
    let _ = hkdf_expand(&prk, b"test_context", 64);
    let _ = hkdf_expand(&prk, data, 128);
    
    // Test key derivation
    let _ = derive_key_256(data, Some(data), b"context");
    
    Ok(())
}
