//! Integration Tests for Sibna Protocol
//!
//! These tests verify the complete protocol flow.

#[cfg(test)]
mod tests {
    use sibna::{SecureContext, Config};
    use tempfile::tempdir;
    use std::sync::Arc;

    fn setup_context(user_id: &str) -> SecureContext {
        let db_path = format!("test_db_{}", user_id);
        let _ = std::fs::create_dir_all(&db_path);

        SecureContext::new(
            Config::default(),
            Some(format!("password_{}", user_id).as_bytes()),
        ).expect("Failed to create context")
    }

    #[test]
    fn test_context_creation() {
        let ctx = setup_context("test_user_1");
        assert!(ctx.create_session(b"peer_1").is_ok());
    }

    #[test]
    fn test_session_creation() {
        let ctx = setup_context("test_user_2");
        let result = ctx.create_session(b"peer_2");
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_handshake_flow() {
        // Create two contexts
        let mut alice = setup_context("alice");
        let bob = setup_context("bob");

        // Generate identity keys
        let alice_id = sibna::keystore::IdentityKeyPair::generate();
        let bob_id = sibna::keystore::IdentityKeyPair::generate();

        // Load identities
        alice.load_identity(
            &alice_id.ed25519_public,
            &alice_id.x25519_public,
            &alice_id.private_seed,
        ).expect("Failed to load Alice identity");

        // Generate prekeys for Bob
        let bob_spk = sibna::keystore::PreKeyPair::generate();
        let bob_opk = sibna::keystore::PreKeyPair::generate();

        // Perform handshake (Alice as initiator)
        let result = alice.perform_handshake(
            b"bob",
            true,  // initiator
            Some(&bob_id.x25519_public),
            Some(&bob_spk.public),
            Some(&bob_opk.public),
            None,
        );

        assert!(result.is_ok(), "Handshake should succeed");
    }

    #[test]
    fn test_encryption_decryption() {
        let ctx = setup_context("test_enc_user");
        ctx.create_session(b"peer_enc").expect("Session creation failed");

        // Without handshake, encryption should fail
        let result = ctx.encrypt_message(b"peer_enc", b"test", None);
        assert!(result.is_err(), "Encryption should fail without handshake");
    }

    #[test]
    fn test_config_defaults() {
        let config = Config::default();

        assert!(config.enable_forward_secrecy);
        assert!(config.enable_post_compromise_security);
        assert_eq!(config.max_skipped_messages, 2000);
        assert_eq!(config.key_rotation_interval, 86400);
        assert_eq!(config.handshake_timeout, 30);
        assert_eq!(config.message_buffer_size, 1024);
    }

    #[test]
    fn test_identity_keypair_generation() {
        let id1 = sibna::keystore::IdentityKeyPair::generate();
        let id2 = sibna::keystore::IdentityKeyPair::generate();

        // Keys should be unique
        assert_ne!(id1.private_seed, id2.private_seed);
        assert_ne!(id1.x25519_public, id2.x25519_public);
        assert_ne!(id1.ed25519_public, id2.ed25519_public);

        // Lengths should be correct
        assert_eq!(id1.private_seed.len(), 32);
        assert_eq!(id1.x25519_public.len(), 32);
        assert_eq!(id1.ed25519_public.len(), 32);
    }

    #[test]
    fn test_identity_signing() {
        let identity = sibna::keystore::IdentityKeyPair::generate();
        let message = b"Test message for signing";

        // Sign and verify
        let signature = identity.sign(message).expect("Signing should succeed");
        assert!(identity.verify(message, &signature), "Signature should be valid");

        // Wrong message should fail
        assert!(!identity.verify(b"Wrong message", &signature), "Wrong message should fail");

        // Wrong signature should fail
        let mut wrong_sig = signature.clone();
        wrong_sig[0] ^= 0xFF;
        assert!(!identity.verify(message, &wrong_sig), "Wrong signature should fail");
    }

    #[test]
    fn test_prekey_generation() {
        let prekey = sibna::keystore::PreKeyPair::generate();

        assert_eq!(prekey.private.len(), 32);
        assert_eq!(prekey.public.len(), 32);
    }

    #[test]
    fn test_signed_prekey() {
        let identity = sibna::keystore::IdentityKeyPair::generate();
        let signed_prekey = sibna::keystore::SignedPreKeyPair::generate_signed(&identity)
            .expect("Signed prekey generation should succeed");

        assert_eq!(signed_prekey.private.len(), 32);
        assert_eq!(signed_prekey.public.len(), 32);
        assert_eq!(signed_prekey.signature.len(), 64);

        // Verify signature
        assert!(signed_prekey.verify_signature(&identity), "Signature should be valid");
    }

    #[test]
    fn test_crypto_handler() {
        use sibna::crypto::CryptoHandler;

        let key = [0x42u8; 32];
        let handler = CryptoHandler::new(&key).expect("Handler creation should succeed");

        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        let ciphertext = handler.encrypt(plaintext, ad).expect("Encryption should succeed");
        let decrypted = handler.decrypt(&ciphertext, ad).expect("Decryption should succeed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_crypto_authentication_failure() {
        use sibna::crypto::CryptoHandler;

        let key = [0x42u8; 32];
        let handler = CryptoHandler::new(&key).expect("Handler creation should succeed");

        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        let ciphertext = handler.encrypt(plaintext, ad).expect("Encryption should succeed");

        // Wrong AD should fail
        let result = handler.decrypt(&ciphertext, b"wrong_ad");
        assert!(result.is_err(), "Wrong AD should cause failure");
    }

    #[test]
    fn test_secure_random() {
        use sibna::crypto::SecureRandom;

        let mut rng1 = SecureRandom::new().expect("RNG creation should succeed");
        let mut rng2 = SecureRandom::new().expect("RNG creation should succeed");

        let bytes1 = rng1.gen_bytes::<32>();
        let bytes2 = rng2.gen_bytes::<32>();

        // Random bytes should differ (extremely high probability)
        assert_ne!(bytes1, bytes2, "Random bytes should be unique");
    }

    #[test]
    fn test_hkdf_derivation() {
        use sibna::crypto::{derive_key_256, hkdf_derive};

        let ikm = b"input key material";
        let salt = b"salt";
        let context = b"context";

        let key1 = derive_key_256(ikm.as_slice(), Some(salt.as_slice()), context)
            .expect("Key derivation should succeed");

        let key2 = derive_key_256(ikm.as_slice(), Some(salt.as_slice()), context)
            .expect("Key derivation should succeed");

        // Same inputs should produce same output
        assert_eq!(key1, key2);

        // Different context should produce different key
        let key3 = derive_key_256(ikm.as_slice(), Some(salt.as_slice()), b"different_context")
            .expect("Key derivation should succeed");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_chain_key() {
        use sibna::ratchet::ChainKey;

        let key = [0x42u8; 32];
        let mut chain = ChainKey::new(key);

        let mk1 = chain.next_message_key();
        let mk2 = chain.next_message_key();
        let mk3 = chain.next_message_key();

        // Each message key should be unique
        assert_ne!(mk1, mk2);
        assert_ne!(mk2, mk3);
        assert_ne!(mk1, mk3);

        // Index should advance
        assert_eq!(chain.index, 3);
    }

    #[test]
    fn test_session_serialization() {
        use sibna::ratchet::DoubleRatchetSession;

        let session = DoubleRatchetSession::new(Config::default())
            .expect("Session creation should succeed");

        let serialized = session.serialize_state()
            .expect("Serialization should succeed");

        let mut restored = DoubleRatchetSession::new(Config::default())
            .expect("Session creation should succeed");

        restored.deserialize_state(&serialized)
            .expect("Deserialization should succeed");
    }
}
