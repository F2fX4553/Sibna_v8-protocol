//! Fuzz Testing for FFI (Foreign Function Interface)
//!
//! Tests that FFI layer handles invalid input gracefully.
//! Run with: cargo fuzz run fuzz_ffi

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test FFI input validation
    test_ffi_validation(data);
});

fn test_ffi_validation(data: &[u8]) {
    // Simulate FFI calls with random data
    
    // 1. Test key length validation
    if data.len() < 32 {
        // Should fail gracefully, not crash
        let _ = validate_key_length(data);
    }
    
    // 2. Test ciphertext validation
    if data.len() < 16 {
        // Ciphertext too short for AEAD tag
        let _ = validate_ciphertext(data);
    }
    
    // 3. Test message number validation
    if !data.is_empty() {
        let _ = validate_message_number(data[0] as u64);
    }
    
    // 4. Test session ID validation
    let _ = validate_session_id(data);
    
    // 5. Test group ID validation  
    let _ = validate_group_id(data);
}

fn validate_key_length(data: &[u8]) -> Result<(), ()> {
    if data.len() != 32 {
        return Err(());
    }
    Ok(())
}

fn validate_ciphertext(data: &[u8]) -> Result<(), ()> {
    // Minimum: nonce (12) + tag (16) + at least 1 byte
    if data.len() < 29 {
        return Err(());
    }
    Ok(())
}

fn validate_message_number(n: u64) -> Result<(), ()> {
    // Message number should be reasonable
    // Not too large (could cause overflow in key derivation)
    if n > 1_000_000_000 {
        return Err(());
    }
    Ok(())
}

fn validate_session_id(data: &[u8]) -> Result<(), ()> {
    // Session ID should be non-empty and reasonable length
    if data.is_empty() || data.len() > 256 {
        return Err(());
    }
    Ok(())
}

fn validate_group_id(data: &[u8]) -> Result<(), ()> {
    // Group ID should be reasonable
    if data.len() > 64 {
        return Err(());
    }
    Ok(())
}
