# API Reference

## Rust API

### SecureContext

Main entry point for the Sibna protocol.

```rust
use sibna::{SecureContext, Config};

// Create context
let config = Config::default();
let mut ctx = SecureContext::new(config, Some(b"password"))?;

// Load identity
ctx.load_identity(&ed_pub, &x_pub, &seed)?;

// Create session
ctx.create_session(b"peer_id")?;

// Perform handshake
let shared_secret = ctx.perform_handshake(
    b"peer_id",
    true,  // initiator
    Some(&peer_identity_key),
    Some(&peer_signed_prekey),
    Some(&peer_onetime_prekey),
    None,  // prologue
)?;

// Encrypt
let ciphertext = ctx.encrypt_message(b"peer_id", b"plaintext", None)?;

// Decrypt
let plaintext = ctx.decrypt_message(b"peer_id", &ciphertext, None)?;
```

### Config

```rust
pub struct Config {
    pub enable_forward_secrecy: bool,
    pub enable_post_compromise_security: bool,
    pub max_skipped_messages: usize,
    pub key_rotation_interval: u64,
    pub handshake_timeout: u64,
    pub message_buffer_size: usize,
}
```

### IdentityKeyPair

```rust
// Generate new identity
let identity = IdentityKeyPair::generate();

// Sign message
let signature = identity.sign(message)?;

// Get X25519 secret for DH
let x25519_secret = identity.get_x25519_secret();
```

### DoubleRatchetSession

```rust
// Create from handshake
let session = DoubleRatchetSession::from_shared_secret(
    &shared_secret,
    local_dh,
    remote_dh,
    config,
)?;

// Encrypt/decrypt
let ciphertext = session.encrypt(plaintext, associated_data)?;
let plaintext = session.decrypt(ciphertext, associated_data)?;

// Serialize/restore
let state = session.serialize_state()?;
session.deserialize_state(&state)?;
```

## Python API

### Client

```python
from sibna import Client

# Create client
client = Client("user_id", "http://server:8000")

# Register
await client.register()

# Send message
await client.send("recipient", b"message")

# Receive messages
messages = await client.receive()

# Background processing
client.on_message(callback)
client.start()
client.stop()
```

## JavaScript/TypeScript API

### Client

```typescript
import { Client } from 'sibna';

// Create client
const client = new Client('userId', 'http://server:8000');

// Register
await client.register();

// Send message
await client.send('recipient', 'message');

// Receive messages
const messages = await client.receive();

// Background processing
client.onMessage(callback);
client.start();
client.stop();
```

## C API

### Context Management

```c
#include <sibna.h>

// Initialize
sibna_init();

// Create context
sibna_context_t* ctx = sibna_context_create(NULL, NULL, 0);

// Free context
sibna_context_free(ctx);
```

### Encryption

```c
// Encrypt
uint8_t* ciphertext;
size_t ciphertext_len;
sibna_error_t err = sibna_context_encrypt(
    ctx,
    session_id, session_id_len,
    plaintext, plaintext_len,
    &ciphertext, &ciphertext_len
);

// Decrypt
uint8_t* plaintext;
size_t plaintext_len;
err = sibna_context_decrypt(
    ctx,
    session_id, session_id_len,
    ciphertext, ciphertext_len,
    &plaintext, &plaintext_len
);

// Free buffers
sibna_free_buffer(ciphertext, ciphertext_len);
sibna_free_buffer(plaintext, plaintext_len);
```

## Error Handling

All APIs return errors for:

- Invalid key lengths
- Encryption/decryption failures
- Session not found
- Key derivation failures
- Invalid state
- Authentication failures

## Constants

| Constant | Value |
|----------|-------|
| KEY_LENGTH | 32 |
| NONCE_LENGTH | 12 |
| TAG_LENGTH | 16 |
| MAX_SKIPPED_MESSAGES | 2000 |
