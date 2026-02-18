//! Fuzz Testing for Group Messaging (Sender Keys)
//!
//! Run with: cargo fuzz run fuzz_group

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::convert::TryInto;

fuzz_target!(|data: &[u8]| {
    // Test sender key operations
    if data.len() >= 32 {
        let _ = test_sender_key(data);
    }
    
    // Test group session
    if data.len() >= 64 {
        let _ = test_group_session(data);
    }
});

fn test_sender_key(data: &[u8]) -> Result<(), ()> {
    use sibna::group::SenderKey;
    
    // Try to create sender key
    if let Ok(mut key) = SenderKey::new() {
        // Derive message keys
        for _ in 0..10 {
            let _mk = key.next_message_key();
        }
    }
    
    // Test key material parsing
    let key_bytes: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    
    // Ensure no crash when using random key material
    let _ = SenderKey::from_bytes(&key_bytes);
    
    Ok(())
}

fn test_group_session(data: &[u8]) -> Result<(), ()> {
    use sibna::group::{GroupManager, GroupId, GroupSession};
    
    // Create group ID from random bytes
    let group_id: GroupId = data[..16].try_into().map_err(|_| ())?;
    
    let mut manager = GroupManager::new();
    
    // Try to create group
    if manager.create_group(group_id).is_ok() {
        // Try to encrypt
        let message = &data[16..];
        let _ = manager.encrypt_group_message(&group_id, message);
    }
    
    // Test with invalid group ID
    let invalid_id: GroupId = [0xFF; 16];
    let _ = manager.encrypt_group_message(&invalid_id, data);
    
    Ok(())
}
