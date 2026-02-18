//! Sibna Protocol - Hello World Example
//!
//! Demonstrates basic usage of the Sibna protocol for secure messaging.

use sibna::{SecureContext, Config, keystore::IdentityKeyPair};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("===========================================");
    println!("Sibna Protocol - Hello World Example");
    println!("===========================================\n");

    // Step 1: Create contexts for Alice and Bob
    println!("[1] Creating secure contexts...");
    let alice_config = Config::default();
    let mut alice_ctx = SecureContext::new(alice_config, Some(b"alice_password"))?;

    let bob_config = Config::default();
    let bob_ctx = SecureContext::new(bob_config, Some(b"bob_password"))?;
    println!("    Done!\n");

    // Step 2: Generate identity keys
    println!("[2] Generating identity keys...");
    let alice_identity = IdentityKeyPair::generate();
    let bob_identity = IdentityKeyPair::generate();
    println!("    Alice X25519: {:02x?}", &alice_identity.x25519_public[..8]);
    println!("    Bob X25519:   {:02x?}", &bob_identity.x25519_public[..8]);
    println!("    Done!\n");

    // Step 3: Load identities
    println!("[3] Loading identities into contexts...");
    alice_ctx.load_identity(
        &alice_identity.ed25519_public,
        &alice_identity.x25519_public,
        &alice_identity.private_seed,
    )?;
    println!("    Done!\n");

    // Step 4: Create sessions
    println!("[4] Creating sessions...");
    alice_ctx.create_session(b"bob")?;
    println!("    Alice -> Bob session created");
    println!("    Done!\n");

    // Step 5: Generate Bob's prekeys
    println!("[5] Generating Bob's prekeys...");
    use sibna::keystore::{PreKeyPair, SignedPreKeyPair};

    let bob_spk = SignedPreKeyPair::generate_signed(&bob_identity)?;
    let bob_opk = PreKeyPair::generate();
    println!("    Signed PreKey: {:02x?}", &bob_spk.public[..8]);
    println!("    One-Time Key:  {:02x?}", &bob_opk.public[..8]);
    println!("    Done!\n");

    // Step 6: Perform X3DH handshake
    println!("[6] Performing X3DH handshake...");
    let shared_secret = alice_ctx.perform_handshake(
        b"bob",
        true,  // Alice is initiator
        Some(&bob_identity.x25519_public),
        Some(&bob_spk.public),
        Some(&bob_opk.public),
        None,
    )?;
    println!("    Shared secret: {:02x?}", &shared_secret[..8]);
    println!("    Done!\n");

    // Step 7: Encrypt a message
    println!("[7] Encrypting message...");
    let plaintext = b"Hello Bob! This is a secret message from Alice.";
    let ciphertext = alice_ctx.encrypt_message(b"bob", plaintext, None)?;
    println!("    Plaintext:  {} bytes", plaintext.len());
    println!("    Ciphertext: {} bytes", ciphertext.len());
    println!("    Done!\n");

    // Step 8: Summary
    println!("===========================================");
    println!("Summary:");
    println!("  - Created secure contexts for Alice and Bob");
    println!("  - Generated identity keys");
    println!("  - Performed X3DH handshake");
    println!("  - Encrypted message successfully");
    println!("===========================================");
    println!("\nProtocol version: 7.0.0");

    Ok(())
}
