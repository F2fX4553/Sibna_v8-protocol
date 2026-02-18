# Protocol Specification

## Overview

Sibna Protocol v7 implements a secure end-to-end encrypted communication protocol based on the Signal Protocol.

## Components

### 1. X3DH Key Agreement

The Extended Triple Diffie-Hellman (X3DH) protocol is used for initial key agreement between two parties.

#### Keys Involved

| Key | Type | Purpose |
|-----|------|---------|
| IK_A, IK_B | Ed25519/X25519 | Long-term identity keys |
| SPK_A, SPK_B | X25519 | Signed prekeys (rotated periodically) |
| OPK_A, OPK_B | X25519 | One-time prekeys (single use) |
| EK_A | X25519 | Ephemeral key (generated per session) |

#### Key Agreement Steps (Initiator)

1. Fetch Bob's prekey bundle: IK_B, SPK_B, signature, OPK_B
2. Verify SPK_B signature with IK_B
3. Generate ephemeral key EK_A
4. Calculate:
   - DH1 = DH(IK_A, SPK_B)
   - DH2 = DH(EK_A, IK_B)
   - DH3 = DH(EK_A, SPK_B)
   - DH4 = DH(EK_A, OPK_B) (if OPK_B available)
5. Derive shared secret: SK = KDF(DH1 || DH2 || DH3 || DH4)

### 2. Double Ratchet

The Double Ratchet algorithm provides forward secrecy and post-compromise security.

#### Symmetric Ratchet

Each message uses a new message key derived from a chain key:

```
Chain Key -> HKDF -> Message Key
         -> HKDF -> Next Chain Key
```

#### DH Ratchet

When a new message is received with a new DH public key:

1. Perform DH(local_key, remote_key)
2. Derive new root key and chain keys
3. Generate new local key pair

### 3. Message Format

```
+----------------+----------------+------------------+------------------+
| DH Public Key  | Message Number | Previous Counter | Encrypted Data   |
| (32 bytes)     | (8 bytes)      | (8 bytes)        | (variable)       |
+----------------+----------------+------------------+------------------+
```

### 4. Encryption

Messages are encrypted using ChaCha20-Poly1305:

- Key: 256-bit message key
- Nonce: Random 96-bit nonce
- Associated Data: Header bytes

## Security Properties

| Property | Description |
|----------|-------------|
| Forward Secrecy | Compromised keys cannot decrypt past messages |
| Post-Compromise Security | Recovery from key compromise |
| Replay Protection | Message counters detect replay attacks |
| Authentication | Ed25519 signatures verify key authenticity |

## Constants

| Constant | Value |
|----------|-------|
| Key Length | 32 bytes (256 bits) |
| Nonce Length | 12 bytes (96 bits) |
| Tag Length | 16 bytes (128 bits) |
| Max Skipped Messages | 2000 |
| Key Rotation Interval | 24 hours |
