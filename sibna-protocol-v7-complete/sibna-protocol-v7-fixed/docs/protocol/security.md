# Security Model

## Threat Model

### Assumptions

1. The network is controlled by an adversary
2. The server is honest-but-curious
3. Endpoints may be compromised temporarily

### Protections

| Threat | Mitigation |
|--------|------------|
| Eavesdropping | End-to-end encryption |
| Man-in-the-middle | Identity key verification |
| Replay attacks | Message counters |
| Key compromise | Forward secrecy, PCS |
| Server compromise | No plaintext on server |

## Cryptographic Choices

### Why ChaCha20-Poly1305?

- Constant-time implementation
- Hardware acceleration on ARM
- 256-bit security level
- Authenticated encryption in one step

### Why X25519?

- Side-channel resistant
- Small key size (32 bytes)
- Fast key generation
- No special validation needed

### Why Ed25519?

- Deterministic signatures
- Fast signing and verification
- Small signatures (64 bytes)
- No random number generator needed for signing

## Key Management

### Key Hierarchy

```
Master Secret
    |
    +-> Root Key
    |       |
    |       +-> Chain Key (Sending)
    |       |       |
    |       |       +-> Message Keys
    |       |
    |       +-> Chain Key (Receiving)
    |               |
    |               +-> Message Keys
    |
    +-> Storage Key (for persistence)
```

### Key Rotation

| Key Type | Rotation Policy |
|----------|-----------------|
| Identity Key | Never (manual) |
| Signed Prekey | Every 7 days |
| One-Time Prekey | After each use |
| Ephemeral Key | Per session |
| Chain Key | Per message |

## Secure Implementation

### Memory Safety

- All sensitive data zeroized on drop
- No `unwrap()` in production code
- Bounds checking on all operations

### Constant-Time Operations

- All cryptographic operations are constant-time
- No branching on secret data
- No memory access patterns based on secrets

### Error Handling

- Errors don't leak sensitive information
- Decryption failures return generic error
- Timing-safe comparison for authentication

## Recommendations

### For Applications

1. Implement key verification (QR codes, safety numbers)
2. Handle network failures gracefully
3. Implement proper session management
4. Store keys securely (encrypted at rest)

### For Deployment

1. Use HTTPS for all server communication
2. Implement rate limiting
3. Use secure headers
4. Enable certificate pinning
