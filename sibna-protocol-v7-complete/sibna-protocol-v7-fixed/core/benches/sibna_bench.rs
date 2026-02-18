//! Benchmarks for Sibna Protocol
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sibna::{SecureContext, Config, crypto::CryptoHandler, keystore::IdentityKeyPair};

fn bench_encryption(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let handler = CryptoHandler::new(&key).unwrap();
    
    let mut group = c.benchmark_group("encryption");
    
    // Different message sizes
    for size in [16, 64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];
        
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| handler.encrypt(black_box(data), b""))
        });
    }
    
    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let handler = CryptoHandler::new(&key).unwrap();
    
    let mut group = c.benchmark_group("decryption");
    
    for size in [16, 64, 256, 1024, 4096].iter() {
        let data = vec![0u8; *size];
        let ciphertext = handler.encrypt(&data, b"").unwrap();
        
        group.bench_with_input(BenchmarkId::new("decrypt", size), &ciphertext, |b, ct| {
            b.iter(|| handler.decrypt(black_box(ct), b""))
        });
    }
    
    group.finish();
}

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("identity_keypair_generation", |b| {
        b.iter(|| IdentityKeyPair::generate())
    });
}

fn bench_key_derivation(c: &mut Criterion) {
    use sibna::crypto::derive_key_256;
    
    let ikm = b"input_key_material";
    let salt = b"salt";
    let context = b"context";
    
    c.bench_function("key_derivation_256", |b| {
        b.iter(|| derive_key_256(
            black_box(ikm.as_slice()),
            Some(black_box(salt.as_slice())),
            black_box(context)
        ))
    });
}

fn bench_handshake(c: &mut Criterion) {
    c.bench_function("x3dh_handshake", |b| {
        b.iter(|| {
            // Simulate handshake components
            let _alice = IdentityKeyPair::generate();
            let _bob = IdentityKeyPair::generate();
            // Full handshake would be benchmarked here
        })
    });
}

fn bench_session_operations(c: &mut Criterion) {
    use sibna::ratchet::DoubleRatchetSession;
    
    c.bench_function("session_creation", |b| {
        b.iter(|| DoubleRatchetSession::new(Config::default()))
    });
    
    c.bench_function("session_serialize", |b| {
        let session = DoubleRatchetSession::new(Config::default()).unwrap();
        b.iter(|| session.serialize_state())
    });
}

fn bench_ratchet_steps(c: &mut Criterion) {
    use sibna::ratchet::ChainKey;
    
    c.bench_function("chain_key_advance", |b| {
        let mut chain = ChainKey::new([0x42u8; 32]);
        b.iter(|| chain.next_message_key())
    });
}

criterion_group!(
    benches,
    bench_encryption,
    bench_decryption,
    bench_key_generation,
    bench_key_derivation,
    bench_handshake,
    bench_session_operations,
    bench_ratchet_steps,
);

criterion_main!(benches);
