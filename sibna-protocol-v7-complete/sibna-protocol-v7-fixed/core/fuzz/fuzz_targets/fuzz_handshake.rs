//! Fuzz Testing for X3DH Handshake
//!
//! Run with: cargo fuzz run fuzz_handshake

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::convert::TryInto;

fuzz_target!(|data: &[u8]| {
    // Test handshake with random key material
    if data.len() >= 128 {
        let _ = test_handshake_random(data);
    }
    
    // Test identity key operations
    if data.len() >= 64 {
        let _ = test_identity_operations(data);
    }
    
    // Test prekey bundle parsing
    if data.len() >= 96 {
        let _ = test_prekey_bundle(data);
    }
});

fn test_handshake_random(data: &[u8]) -> Result<(), ()> {
    use x25519_dalek::{PublicKey, StaticSecret};
    
    // Try to create keys from random bytes
    let identity_secret: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    let ephemeral_secret: [u8; 32] = data[32..64].try_into().map_err(|_| ())?;
    
    let identity_key = StaticSecret::from(identity_secret);
    let ephemeral_key = StaticSecret::from(ephemeral_secret);
    
    // Test DH operations
    let public_identity = PublicKey::from(&identity_key);
    let public_ephemeral = PublicKey::from(&ephemeral_key);
    
    // Perform DH
    let _dh1 = identity_key.diffie_hellman(&public_ephemeral);
    let _dh2 = ephemeral_key.diffie_hellman(&&public_identity);
    
    Ok(())
}

fn test_identity_operations(data: &[u8]) -> Result<(), ()> {
    use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
    
    let secret_bytes: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    let message = &data[32..64];
    
    // Try to create signing key
    if let Ok(signing_key) = SigningKey::from_bytes(&secret_bytes) {
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        // Sign and verify
        let signature = signing_key.sign(message);
        let _ = verifying_key.verify(message, &signature);
        
        // Try to verify with wrong message
        let wrong_msg = b"wrong message";
        let _ = verifying_key.verify(wrong_msg, &signature);
    }
    
    Ok(())
}

fn test_prekey_bundle(data: &[u8]) -> Result<(), ()> {
    // Simulate parsing a prekey bundle from untrusted input
    let _identity_key: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    let _signed_prekey: [u8; 32] = data[32..64].try_into().map_err(|_| ())?;
    let _signature: [u8; 64] = data[64..128].try_into().map_err(|_| ())?;
    
    // In real implementation, would verify signature here
    // For fuzz, just ensure no crashes/panics
    
    Ok(())
}
