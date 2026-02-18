//! Fuzz Testing for Session State

#![no_main]

use libfuzzer_sys::fuzz_target;
use sibna::{Config, ratchet::DoubleRatchetSession};

fuzz_target!(|data: &[u8]| {
    // Test session deserialization with random data
    if let Ok(mut session) = DoubleRatchetSession::new(Config::default()) {
        let _ = session.deserialize_state(data);
    }
    
    // Test serialization roundtrip
    if let Ok(session) = DoubleRatchetSession::new(Config::default()) {
        if let Ok(serialized) = session.serialize_state() {
            let mut restored = DoubleRatchetSession::new(Config::default()).unwrap();
            let _ = restored.deserialize_state(&serialized);
        }
    }
});
