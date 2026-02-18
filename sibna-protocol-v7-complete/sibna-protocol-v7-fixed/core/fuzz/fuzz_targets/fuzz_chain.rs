//! Fuzz Testing for Chain Key Operations
//!
//! Run with: cargo fuzz run fuzz_chain

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::convert::TryInto;

fuzz_target!(|data: &[u8]| {
    // Test chain key derivation
    if data.len() >= 32 {
        let _ = test_chain_key(data);
    }
    
    // Test ratchet state
    if data.len() >= 64 {
        let _ = test_ratchet_state(data);
    }
});

fn test_chain_key(data: &[u8]) -> Result<(), ()> {
    use sibna::ratchet::ChainKey;
    
    let key: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    
    let mut chain = ChainKey::new(key);
    
    // Derive many message keys
    for _ in 0..100 {
        let _mk = chain.next_message_key();
    }
    
    // Verify index advanced
    if chain.index() != 100 {
        return Err(());
    }
    
    Ok(())
}

fn test_ratchet_state(data: &[u8]) -> Result<(), ()> {
    use sibna::ratchet::RatchetState;
    
    let root_key: [u8; 32] = data[..32].try_into().map_err(|_| ())?;
    let chain_key: [u8; 32] = data[32..64].try_into().map_err(|_| ())?;
    
    // Create state
    let state = RatchetState::new(root_key, chain_key);
    
    // Serialize and deserialize
    let serialized = state.serialize();
    let _restored = RatchetState::deserialize(&serialized);
    
    Ok(())
}
