# Sibna Protocol v7 - Complete Technical Documentation

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [X3DH Key Agreement](#x3dh-key-agreement)
5. [Double Ratchet Algorithm](#double-ratchet-algorithm)
6. [Group Messaging](#group-messaging)
7. [Security Properties](#security-properties)
8. [API Reference](#api-reference)
9. [Integration Guide](#integration-guide)
10. [Security Considerations](#security-considerations)

---

## 1. Overview

Sibna Protocol v7 is a secure end-to-end encrypted messaging protocol implementing the Signal Protocol architecture. It provides:

- **Confidentiality**: Messages cannot be read by anyone except intended recipients
- **Integrity**: Any modification to messages is detected
- **Authenticity**: Recipients can verify sender identity
- **Forward Secrecy**: Past messages remain secure even if keys are compromised
- **Post-Compromise Security**: Sessions recover after temporary key compromise

### Version Information

| Component | Version |
|-----------|---------|
| Protocol Version | 7.0.0 |
| X3DH | 1.0 (Signal compatible) |
| Double Ratchet | 1.0 (Signal compatible) |
| Encryption | ChaCha20-Poly1305 |

---

## 2. Architecture

### 2.1 System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                      SecureContext                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   KeyStore   │  │SessionManager│  │ GroupManager │          │
│  │  (Encrypted) │  │  (Ratchet)   │  │ (Sender Keys)│          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                │                  │                   │
│         ▼                ▼                  ▼                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Crypto Handler                         │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │  │
│  │  │ ChaCha20│  │ Blake3  │  │ X25519  │  │  Ed25519    │  │  │
│  │  │Poly1305 │  │  KDF    │  │   DH    │  │  Signatures │  │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
Sender                                    Receiver
  │                                          │
  │  1. Get Identity Key                     │
  │  2. Perform X3DH Handshake               │
  │ ─────────────────────────────────────────▶
  │     (Exchange public keys)               │
  │                                          │
  │  3. Initialize Double Ratchet            │
  │  4. Encrypt Message                      │
  │ ─────────────────────────────────────────▶
  │     (Encrypted message)                  │
  │                                          │  5. Decrypt Message
  │                                          │  6. Verify Sender
  │                                          │
```

---

## 3. Cryptographic Primitives

### 3.1 Key Exchange: X25519

X25519 is a Diffie-Hellman key exchange function using Curve25519.

**Properties:**
- 256-bit keys
- 128-bit security level
- Constant-time implementation
- Resistant to side-channel attacks

**Usage:**
```rust
use x25519_dalek::{PublicKey, StaticSecret};

// Generate key pair
let secret = StaticSecret::random_from_rng(OsRng);
let public = PublicKey::from(&secret);

// Perform DH
let shared_secret = secret.diffie_hellman(&their_public);
```

### 3.2 Signatures: Ed25519

Ed25519 is used for signing prekeys and identity verification.

**Properties:**
- 256-bit keys
- 128-bit security level
- Deterministic signatures
- Fast verification

**Usage:**
```rust
use ed25519_dalek::{SigningKey, Signature};

let signing_key = SigningKey::generate(&mut OsRng);
let signature = signing_key.sign(message);
let valid = signing_key.verifying_key().verify(message, &signature).is_ok();
```

### 3.3 Encryption: ChaCha20-Poly1305

Authenticated encryption with associated data (AEAD).

**Properties:**
- 256-bit key
- 96-bit nonce
- 128-bit authentication tag
- Constant-time decryption

**Message Format:**
```
┌─────────────┬──────────────────┬─────────────┐
│  Nonce (12) │  Ciphertext (N)  │  Tag (16)   │
└─────────────┴──────────────────┴─────────────┘
```

### 3.4 Key Derivation: HKDF-Blake3

Blake3-based HKDF for deriving keys.

**Properties:**
- 256-bit output
- Collision-resistant
- Fast software implementation

**Usage:**
```rust
use blake3;

let derived = blake3::keyed_hash(&key, info);
```

---

## 4. X3DH Key Agreement

### 4.1 Overview

X3DH (Extended Triple Diffie-Hellman) establishes a shared secret between two parties using:

1. **Identity Keys (IK)**: Long-term identity keys
2. **Signed Prekeys (SPK)**: Medium-term keys signed by identity
3. **One-time Prekeys (OPK)**: Single-use keys

### 4.2 Key Bundle

```
┌─────────────────────────────────────────────────────┐
│                   Prekey Bundle                      │
├─────────────────────────────────────────────────────┤
│  Identity Key (IK)         : 32 bytes               │
│  Signed Prekey (SPK)       : 32 bytes               │
│  SPK Signature             : 64 bytes               │
│  One-time Prekey (OPK)     : 32 bytes (optional)    │
└─────────────────────────────────────────────────────┘
```

### 4.3 Key Agreement Process

**Initiator (Alice):**
```
1. Fetch Bob's prekey bundle
2. Verify SPK signature with Bob's IK
3. Generate ephemeral key (EK_A)
4. Calculate shared secret:
   DH1 = DH(IK_A, SPK_B)
   DH2 = DH(EK_A, IK_B)
   DH3 = DH(EK_A, SPK_B)
   DH4 = DH(IK_A, OPK_B) [if available]
   
   SK = KDF(DH1 || DH2 || DH3 || DH4)
```

**Receiver (Bob):**
```
1. Receive Alice's initial message
2. Calculate same shared secret:
   DH1 = DH(SPK_B, IK_A)
   DH2 = DH(IK_B, EK_A)
   DH3 = DH(SPK_B, EK_A)
   DH4 = DH(OPK_B, IK_A) [if used]
   
   SK = KDF(DH1 || DH2 || DH3 || DH4)
```

### 4.4 Security Properties

| Property | How Achieved |
|----------|--------------|
| Mutual Authentication | Identity keys in DH calculations |
| Forward Secrecy | Ephemeral keys in DH3, DH4 |
| Key Compromise Impersonation Resistance | Identity key required |

---

## 5. Double Ratchet Algorithm

### 5.1 Overview

The Double Ratchet provides ongoing key management after X3DH:

1. **Symmetric Key Ratchet**: New key per message
2. **DH Ratchet**: New DH exchange on each turn

### 5.2 Ratchet State

```rust
struct RatchetState {
    // Root key for DH ratchet
    root_key: [u8; 32],
    
    // Sending chain
    sending_chain: Option<ChainKey>,
    
    // Receiving chain
    receiving_chain: Option<ChainKey>,
    
    // Local DH key pair
    dh_local: Option<StaticSecret>,
    
    // Remote DH public key
    dh_remote: Option<PublicKey>,
    
    // Skipped message keys (for out-of-order)
    skipped_keys: HashMap<(PublicKey, u64), [u8; 32]>,
}
```

### 5.3 Message Encryption

```
Encrypt(plaintext, AD):
  1. Get message key from sending chain
     MK = HMAC(ChainKey, 0x01)
     
  2. Advance chain key
     ChainKey' = HMAC(ChainKey, 0x02)
     
  3. Encrypt with message key
     Ciphertext = ChaCha20-Poly1305(MK, plaintext, AD)
     
  4. Include header
     Header = (DH_public, chain_index, prev_chain_len)
     
  5. Return (Header, Ciphertext)
```

### 5.4 Message Decryption

```
Decrypt(header, ciphertext, AD):
  1. Check if DH key changed
     If new DH key:
       - Perform DH ratchet step
       - Reset receiving chain
       
  2. Check message number
     If message number matches expected:
       - Use current chain key
     Else if in skipped keys:
       - Use cached message key
     Else:
       - Advance chain, cache skipped keys
       
  3. Get message key
  4. Decrypt ciphertext
  5. Return plaintext
```

### 5.5 DH Ratchet Step

```
DH_Ratchet(their_new_public):
  1. Generate new local key pair
     (sk_new, pk_new) = generate_dh_keypair()
     
  2. Calculate new shared secret
     dh1 = DH(sk_local, their_new_public)  // Receiving
     dh2 = DH(sk_new, their_new_public)    // Sending
     
  3. Derive new keys
     (root_key, chain_key_send) = KDF(root_key, dh2)
     (root_key, chain_key_recv) = KDF(root_key, dh1)
     
  4. Update state
     dh_local = sk_new
     dh_remote = their_new_public
     sending_chain = chain_key_send
     receiving_chain = chain_key_recv
```

---

## 6. Group Messaging

### 6.1 Sender Keys

Group messaging uses Sender Keys for efficient group encryption:

```
┌─────────────────────────────────────────────────────┐
│                   Sender Key                         │
├─────────────────────────────────────────────────────┤
│  Chain Key      : 32 bytes                          │
│  Signature Key  : 32 bytes                          │
│  Message Number : u64                               │
└─────────────────────────────────────────────────────┘
```

### 6.2 Group Session Setup

```
1. Group creator generates sender key
2. Sender key is encrypted for each member:
   For each member:
     EncryptedKey = ChaCha20-Poly1305(
       DoubleRatchet(member).Encrypt(sender_key)
     )
3. Members receive and store sender key
```

### 6.3 Group Message Encryption

```
1. Derive message key from sender key chain
2. Encrypt message with message key
3. Sign ciphertext with signature key
4. Broadcast to all group members
```

### 6.4 Group Message Decryption

```
1. Verify signature with sender's public key
2. Get sender key for this sender
3. Derive message key (advance chain if needed)
4. Decrypt message
```

---

## 7. Security Properties

### 7.1 Forward Secrecy

**Achieved By:**
- Ephemeral keys in X3DH
- Per-message key derivation in Double Ratchet
- Chain key advancement after each message

**Result:**
Compromise of current keys does NOT reveal past messages.

### 7.2 Post-Compromise Security

**Achieved By:**
- DH ratchet generates new key material
- New DH exchange on each ratchet step

**Result:**
Session recovers security after compromise when DH ratchet advances.

### 7.3 Replay Protection

**Achieved By:**
- Message numbers in headers
- Skipped message key cache
- Detection of duplicate message numbers

**Result:**
Old messages cannot be re-sent successfully.

### 7.4 Authentication

**Achieved By:**
- Identity keys in X3DH
- Signed prekeys
- Message authentication tags

**Result:**
Messages can be verified as coming from claimed sender.

---

## 8. API Reference

### 8.1 Core Types

```rust
// Main context
pub struct SecureContext { ... }

// Configuration
pub struct Config {
    pub enable_forward_secrecy: bool,
    pub enable_post_compromise_security: bool,
    pub max_skipped_messages: usize,
    pub key_rotation_interval: u64,
    pub handshake_timeout: u64,
    pub message_buffer_size: usize,
    pub enable_group_messaging: bool,
    pub max_group_size: usize,
    pub db_path: Option<String>,
}

// Identity
pub struct IdentityKeyPair {
    pub ed25519_public: [u8; 32],
    pub ed25519_secret: [u8; 32],
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
}

// Safety number for verification
pub struct SafetyNumber { ... }
```

### 8.2 Core Functions

```rust
// Create context
impl SecureContext {
    pub fn new(config: Config, master_password: Option<&[u8]>) -> ProtocolResult<Self>;
    
    // Identity management
    pub fn generate_identity(&mut self) -> ProtocolResult<IdentityKeyPair>;
    pub fn get_identity(&self) -> ProtocolResult<IdentityKeyPair>;
    
    // Handshake
    pub fn perform_handshake(
        &self,
        peer_id: &[u8],
        initiator: bool,
        peer_identity_key: Option<&[u8]>,
        peer_signed_prekey: Option<&[u8]>,
        peer_onetime_prekey: Option<&[u8]>,
        prologue: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>>;
    
    // Messaging
    pub fn encrypt_message(
        &self,
        session_id: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>>;
    
    pub fn decrypt_message(
        &self,
        session_id: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>>;
    
    // Groups
    pub fn create_group(&self, group_id: [u8; 32]) -> ProtocolResult<()>;
    pub fn add_group_member(&self, group_id: &[u8; 32], public_key: [u8; 32]) -> ProtocolResult<()>;
    pub fn encrypt_group_message(&self, group_id: &[u8; 32], plaintext: &[u8]) -> ProtocolResult<GroupMessage>;
    pub fn decrypt_group_message(&self, message: &GroupMessage, sender_public_key: &[u8; 32]) -> ProtocolResult<Vec<u8>>;
}
```

### 8.3 Safety Number

```rust
impl SafetyNumber {
    // Calculate safety number for verification
    pub fn calculate(our_identity: &[u8; 32], their_identity: &[u8; 32]) -> Self;
    
    // Display format (XXXXX XXXXX XXXXX...)
    pub fn as_string(&self) -> &str;
    
    // Verify two safety numbers match
    pub fn verify(&self, other: &SafetyNumber) -> bool;
}
```

---

## 9. Integration Guide

### 9.1 Python SDK

```python
from sibna import SecureContext, Config

# Initialize
config = Config()
ctx = SecureContext(config, b"master_password")

# Generate identity
identity = ctx.generate_identity()
print(f"My public key: {identity.x25519_public.hex()}")

# Create session and handshake
session = ctx.create_session(b"peer_id")
# ... exchange keys with peer ...

# Encrypt/Decrypt
ciphertext = ctx.encrypt_message(b"peer_id", b"Hello!", None)
plaintext = ctx.decrypt_message(b"peer_id", ciphertext, None)
```

### 9.2 JavaScript SDK

```javascript
const { SecureContext, Config } = require('sibna');

// Initialize
const config = new Config();
const ctx = new SecureContext(config, 'master_password');

// Generate identity
const identity = ctx.generateIdentity();
console.log('Public key:', identity.x25519_public.toString('hex'));

// Messaging
const ciphertext = ctx.encryptMessage(peerId, 'Hello!', null);
const plaintext = ctx.decryptMessage(peerId, ciphertext, null);
```

### 9.3 Rust Direct

```rust
use sibna::{SecureContext, Config, SafetyNumber};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let config = Config::default();
    let mut ctx = SecureContext::new(config, Some(b"master_password"))?;
    
    // Generate identity
    let identity = ctx.generate_identity()?;
    
    // Safety number for verification
    let safety = SafetyNumber::calculate(
        &identity.x25519_public,
        &peer_identity,
    );
    println!("Safety number: {}", safety.as_string());
    
    // Messaging
    let ciphertext = ctx.encrypt_message(b"peer_id", b"Hello!", None)?;
    let plaintext = ctx.decrypt_message(b"peer_id", &ciphertext, None)?;
    
    Ok(())
}
```

---

## 10. Security Considerations

### 10.1 Key Storage

- Keys are stored encrypted using ChaCha20-Poly1305
- Storage encryption key derived from master password
- Keys are zeroized from memory after use

### 10.2 Random Number Generation

- Uses OS-provided CSPRNG (OsRng)
- No custom random number generators
- Constant-time operations where required

### 10.3 Input Validation

All external inputs are validated:
- Key lengths (must be exactly 32 bytes)
- Message sizes (max 10 MB)
- Session IDs (max 256 bytes)
- Ciphertext format (minimum 29 bytes)

### 10.4 Rate Limiting

Built-in rate limiting prevents:
- Brute force attacks
- Resource exhaustion
- DoS attacks

### 10.5 Known Limitations

| Limitation | Mitigation |
|------------|------------|
| Metadata exposure | Use additional anonymity layers |
| Endpoint compromise | User device security |
| No post-quantum | Future: Kyber integration |
| Group size limits | Use separate groups for large audiences |

---

## Appendix A: Error Codes

| Code | Error | Description |
|------|-------|-------------|
| E001 | InvalidKeyLength | Key has wrong length |
| E002 | SessionNotFound | Session does not exist |
| E003 | DecryptionFailed | Message decryption failed |
| E004 | InvalidSignature | Signature verification failed |
| E005 | RateLimited | Too many requests |
| E006 | InvalidState | Invalid session state |
| E007 | StorageError | Database error |
| E008 | KeyDerivationFailed | KDF operation failed |

## Appendix B: Constants

```rust
// Protocol version
pub const VERSION: &str = "7.0.0";

// Key sizes
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = 64;

// Limits
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_GROUP_SIZE: usize = 256;
pub const MAX_SKIPPED_MESSAGES: usize = 2000;
```

## Appendix C: References

1. Signal Protocol: https://signal.org/docs/
2. X3DH Specification: https://signal.org/docs/specifications/x3dh/
3. Double Ratchet: https://signal.org/docs/specifications/doubleratchet/
4. ChaCha20-Poly1305: RFC 8439
5. X25519: RFC 7748
6. Ed25519: RFC 8032
