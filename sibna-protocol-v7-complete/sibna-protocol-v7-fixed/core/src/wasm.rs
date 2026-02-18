//! WASM Bindings for Sibna Protocol
//!
//! Provides WebAssembly bindings for use in browsers and Node.js.

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

// Import the core library
use crate::{SecureContext, Config, IdentityKeyPair, GroupMessage};

/// WASM-compatible configuration
#[wasm_bindgen]
pub struct WasmConfig {
    enable_forward_secrecy: bool,
    enable_group_messaging: bool,
    max_skipped_messages: usize,
}

#[wasm_bindgen]
impl WasmConfig {
    /// Create default configuration
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            enable_forward_secrecy: true,
            enable_group_messaging: true,
            max_skipped_messages: 2000,
        }
    }

    /// Set forward secrecy
    pub fn with_forward_secrecy(mut self, enabled: bool) -> Self {
        self.enable_forward_secrecy = enabled;
        self
    }

    /// Set group messaging
    pub fn with_group_messaging(mut self, enabled: bool) -> Self {
        self.enable_group_messaging = enabled;
        self
    }
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl From<WasmConfig> for Config {
    fn from(config: WasmConfig) -> Self {
        let mut c = Config::default();
        c.enable_forward_secrecy = config.enable_forward_secrecy;
        c.enable_group_messaging = config.enable_group_messaging;
        c.max_skipped_messages = config.max_skipped_messages;
        c
    }
}

/// WASM-compatible SecureContext
#[wasm_bindgen]
pub struct WasmContext {
    inner: SecureContext,
}

#[wasm_bindgen]
impl WasmContext {
    /// Create a new context
    #[wasm_bindgen(constructor)]
    pub fn new(config: WasmConfig) -> Result<WasmContext, JsValue> {
        let cfg: Config = config.into();
        
        // In WASM, use in-memory storage
        #[cfg(target_arch = "wasm32")]
        {
            SecureContext::new_in_memory(cfg)
                .map(|ctx| WasmContext { inner: ctx })
                .map_err(|e| JsValue::from_str(&format!("Failed to create context: {:?}", e)))
        }
        
        #[cfg(not(target_arch = "wasm32"))]
        {
            SecureContext::new(cfg, None)
                .map(|ctx| WasmContext { inner: ctx })
                .map_err(|e| JsValue::from_str(&format!("Failed to create context: {:?}", e)))
        }
    }

    /// Generate a new identity
    pub fn generate_identity(&mut self) -> Result<JsValue, JsValue> {
        let identity = self.inner.generate_identity()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate identity: {:?}", e)))?;

        let result = serde_wasm_bindgen::to_value(&IdentityInfo {
            private_seed: hex::encode(&identity.private_seed),
            ed25519_public: hex::encode(&identity.ed25519_public),
            x25519_public: hex::encode(&identity.x25519_public),
        }).map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;

        Ok(result)
    }

    /// Create a session
    pub fn create_session(&self, peer_id: &str) -> Result<(), JsValue> {
        self.inner.create_session(peer_id.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Failed to create session: {:?}", e)))
    }

    /// Perform handshake as initiator
    pub fn perform_handshake_initiator(
        &self,
        peer_id: &str,
        peer_identity_key: &str,
        peer_signed_prekey: &str,
        peer_onetime_prekey: &str,
    ) -> Result<String, JsValue> {
        let ik = hex::decode(peer_identity_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid identity key: {:?}", e)))?;
        let spk = hex::decode(peer_signed_prekey)
            .map_err(|e| JsValue::from_str(&format!("Invalid signed prekey: {:?}", e)))?;
        let opk = hex::decode(peer_onetime_prekey)
            .map_err(|e| JsValue::from_str(&format!("Invalid onetime prekey: {:?}", e)))?;

        let secret = self.inner.perform_handshake(
            peer_id.as_bytes(),
            true,
            Some(&ik),
            Some(&spk),
            Some(&opk),
            None,
        ).map_err(|e| JsValue::from_str(&format!("Handshake failed: {:?}", e)))?;

        Ok(hex::encode(secret))
    }

    /// Encrypt a message
    pub fn encrypt(&self, peer_id: &str, plaintext: &str) -> Result<String, JsValue> {
        let ciphertext = self.inner.encrypt_message(
            peer_id.as_bytes(),
            plaintext.as_bytes(),
            None,
        ).map_err(|e| JsValue::from_str(&format!("Encryption failed: {:?}", e)))?;

        Ok(hex::encode(ciphertext))
    }

    /// Decrypt a message
    pub fn decrypt(&self, peer_id: &str, ciphertext: &str) -> Result<String, JsValue> {
        let data = hex::decode(ciphertext)
            .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext: {:?}", e)))?;

        let plaintext = self.inner.decrypt_message(
            peer_id.as_bytes(),
            &data,
            None,
        ).map_err(|e| JsValue::from_str(&format!("Decryption failed: {:?}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8: {:?}", e)))
    }

    /// Create a group
    pub fn create_group(&self, group_id: &str) -> Result<(), JsValue> {
        let id = hex::decode(group_id)
            .and_then(|v| {
                let mut arr = [0u8; 32];
                if v.len() == 32 {
                    arr.copy_from_slice(&v);
                    Ok(arr)
                } else {
                    Err(hex::FromHexError::InvalidStringLength)
                }
            })
            .map_err(|e| JsValue::from_str(&format!("Invalid group ID: {:?}", e)))?;

        self.inner.create_group(id)
            .map_err(|e| JsValue::from_str(&format!("Failed to create group: {:?}", e)))
    }

    /// Encrypt a group message
    pub fn encrypt_group(&self, group_id: &str, plaintext: &str) -> Result<String, JsValue> {
        let id = parse_group_id(group_id)?;
        
        let message = self.inner.encrypt_group_message(&id, plaintext.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Group encryption failed: {:?}", e)))?;

        serde_json::to_string(&message)
            .map_err(|e| JsValue::from_str(&format!("Serialization failed: {:?}", e)))
    }

    /// Add member to group
    pub fn add_group_member(&self, group_id: &str, public_key: &str) -> Result<(), JsValue> {
        let id = parse_group_id(group_id)?;
        let pk = parse_public_key(public_key)?;

        self.inner.add_group_member(&id, pk)
            .map_err(|e| JsValue::from_str(&format!("Failed to add member: {:?}", e)))
    }

    /// Get device ID
    pub fn device_id(&self) -> String {
        hex::encode(self.inner.device_id())
    }

    /// Get protocol version
    pub fn version() -> String {
        crate::VERSION.to_string()
    }
}

/// Identity information for serialization
#[derive(Serialize, Deserialize)]
pub struct IdentityInfo {
    pub private_seed: String,
    pub ed25519_public: String,
    pub x25519_public: String,
}

/// Helper: parse group ID
fn parse_group_id(s: &str) -> Result<[u8; 32], JsValue> {
    hex::decode(s)
        .and_then(|v| {
            let mut arr = [0u8; 32];
            if v.len() == 32 {
                arr.copy_from_slice(&v);
                Ok(arr)
            } else {
                Err(hex::FromHexError::InvalidStringLength)
            }
        })
        .map_err(|e| JsValue::from_str(&format!("Invalid group ID: {:?}", e)))
}

/// Helper: parse public key
fn parse_public_key(s: &str) -> Result<[u8; 32], JsValue> {
    hex::decode(s)
        .and_then(|v| {
            let mut arr = [0u8; 32];
            if v.len() == 32 {
                arr.copy_from_slice(&v);
                Ok(arr)
            } else {
                Err(hex::FromHexError::InvalidStringLength)
            }
        })
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))
}

/// Initialize WASM module
#[wasm_bindgen(start)]
pub fn init() {
    // Set panic hook for better error messages
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Generate random bytes
#[wasm_bindgen]
pub fn random_bytes(len: usize) -> Result<String, JsValue> {
    use crate::crypto::SecureRandom;
    
    let mut rng = SecureRandom::new()
        .map_err(|e| JsValue::from_str(&format!("RNG error: {:?}", e)))?;
    
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    
    Ok(hex::encode(bytes))
}

/// Generate a key pair
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let identity = IdentityKeyPair::generate();
    
    serde_wasm_bindgen::to_value(&IdentityInfo {
        private_seed: hex::encode(&identity.private_seed),
        ed25519_public: hex::encode(&identity.ed25519_public),
        x25519_public: hex::encode(&identity.x25519_public),
    }).map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))
}
