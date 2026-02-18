# Sibna Protocol v7 - Threat Model

## Document Information
- **Version**: 1.0
- **Date**: 2024
- **Classification**: Security Documentation

---

## 1. Executive Summary

This document defines the threat model for Sibna Protocol v7, a cryptographic messaging protocol implementing X3DH key agreement and Double Ratchet algorithm. Understanding what we protect against is essential for proper security assessment.

---

## 2. System Overview

### 2.1 Components
```
┌─────────────────────────────────────────────────────────────┐
│                        Sibna Protocol                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   X3DH      │───▶│   Double    │───▶│   ChaCha20  │     │
│  │  Handshake  │    │   Ratchet   │    │  -Poly1305  │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                  │                  │             │
│         ▼                  ▼                  ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  Identity   │    │   Session   │    │   Message   │     │
│  │   Keys      │    │   State     │    │  Encrypt    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Trust Assumptions
- Users trust their own devices
- Server is NOT trusted for message content
- Network is considered hostile

---

## 3. Attacker Profiles

### 3.1 Network Attacker ( passive )
**Capabilities:**
- Can intercept all network traffic
- Can observe message metadata (size, timing, sender/recipient)
- Can record encrypted messages for later analysis

**What They CAN Do:**
- Traffic analysis
- Metadata correlation
- Store ciphertext for future attacks

**What They CANNOT Do:**
- Decrypt messages without keys
- Impersonate users without identity keys
- Modify messages without detection

**Protection Status:** ✅ PROTECTED by end-to-end encryption

---

### 3.2 Network Attacker ( active / MITM )
**Capabilities:**
- All passive attacker capabilities, PLUS:
- Can modify, delete, or inject messages
- Can block delivery
- Can replay old messages

**What They CAN Do:**
- Denial of service
- Replay attacks (if not protected)
- Message injection attempts

**What They CANNOT Do:**
- Forge valid messages from legitimate users
- Decrypt intercepted messages
- Successfully modify messages without detection

**Protection Status:** ✅ PROTECTED by authentication tags and replay protection

---

### 3.3 Compromised Server
**Capabilities:**
- Full control over message routing
- Access to all stored data
- Can refuse service to specific users
- Can observe connection patterns

**What They CAN Do:**
- Metadata analysis (who talks to whom, when, how often)
- Denial of service
- Store prekey bundles
- Delay or block message delivery

**What They CANNOT Do:**
- Read message content
- Forge messages from users
- Derive past or future session keys (without device compromise)

**Protection Status:** ✅ PROTECTED by end-to-end encryption and Double Ratchet

---

### 3.4 Device Thief
**Capabilities:**
- Physical access to unlocked device
- Can read all stored data
- Can extract keys from storage

**What They CAN Do:**
- Read all stored messages
- Impersonate the user (if unlocked)
- Extract identity keys

**What They CANNOT Do:**
- Decrypt messages from BEFORE the theft (Forward Secrecy)
- Continue impersonation after key rotation

**Protection Status:** ⚠️ PARTIAL - Forward Secrecy protects past messages, but current session may be compromised

---

### 3.5 Memory Extractor
**Capabilities:**
- Can read process memory (malware, debugger, cold boot attack)
- Can capture runtime state

**What They CAN Do:**
- Extract current session keys
- Capture ratchet state
- Read plaintext messages in transit

**What They CANNOT Do:**
- Recover keys that were properly zeroized
- Access messages already deleted from memory

**Protection Status:** ⚠️ PARTIAL - Keys should be zeroized after use, but memory protection is OS-dependent

---

### 3.6 State-Level Adversary
**Capabilities:**
- All previous capabilities combined
- Legal coercion for backdoors
- Zero-day exploits
- Physical device implantation

**What They CAN Do:**
- Targeted device compromise
- Legal pressure on developers/operators
- Supply chain attacks

**What They CANNOT Do:**
- Bulk decryption without individual device compromise
- Break ChaCha20-Poly1305 directly
- Compromise Double Ratchet mathematically

**Protection Status:** ⚠️ LIMITED - Protocol is secure, but endpoint security depends on user

---

## 4. Assets and Protection Goals

### 4.1 Primary Assets

| Asset | Sensitivity | Protection Mechanism |
|-------|-------------|---------------------|
| Message Content | CRITICAL | ChaCha20-Poly1305 encryption |
| Identity Keys | CRITICAL | Secure storage, never transmitted |
| Session Keys | HIGH | Derived via HKDF, rotated per message |
| Prekeys | MEDIUM | One-time use, server-stored |
| Message Metadata | MEDIUM | Not protected (server sees it) |
| User Identities | LOW | Public keys are public |

### 4.2 What We Protect

✅ **Confidentiality** - Message content cannot be read by anyone except intended recipient

✅ **Integrity** - Any modification to messages is detected

✅ **Authenticity** - Recipient can verify sender identity

✅ **Forward Secrecy** - Compromise of current keys does not expose past messages

✅ **Post-Compromise Security** - Session recovers after temporary key compromise

✅ **Replay Protection** - Old messages cannot be re-sent successfully

### 4.3 What We Do NOT Protect

❌ **Metadata Privacy** - Server knows who communicates with whom and when

❌ **Traffic Analysis** - Message sizes and timing are visible

❌ **Endpoint Security** - We cannot protect against compromised devices

❌ **Denial of Service** - Server can always refuse service

❌ **Social Engineering** - Users can be tricked into revealing information

---

## 5. Security Assumptions

### 5.1 Cryptographic Assumptions

```
Assumption                          Strength
─────────────────────────────────────────────────
X25519 ECDH                        128-bit security
Ed25519 Signatures                 128-bit security  
ChaCha20-Poly1305                  256-bit key, 128-bit tag
HKDF-SHA256                        256-bit output
Blake3                             256-bit output
```

### 5.2 Trust Assumptions

| Assumption | Risk if Violated |
|------------|------------------|
| Users verify each other's identity keys | MITM during initial handshake |
| Device is not compromised | All security broken |
| Random number generator is secure | Predictable keys |
| Cryptographic libraries are correct | Implementation flaws |

### 5.3 Operational Assumptions

- Server distributes prekeys honestly
- Users do not share private keys
- Clocks are roughly synchronized for timestamp validation
- Message ordering is eventually consistent

---

## 6. Threat Scenarios

### Scenario 1: Passive Network Surveillance
```
Attacker: Network Attacker (passive)
Goal: Read message content
Attack: Capture all traffic

Defense: ChaCha20-Poly1305 encryption
Result: ✅ ATTACK FAILED - Ciphertext is indistinguishable from random
```

### Scenario 2: Replay Attack
```
Attacker: Network Attacker (active)
Goal: Re-send old message, confuse recipient
Attack: Capture and re-transmit valid message

Defense: Message numbers in Double Ratchet + replay cache
Result: ✅ ATTACK FAILED - Duplicate message number detected
```

### Scenario 3: Key Compromise
```
Attacker: Device Thief
Goal: Decrypt all messages (past and future)
Attack: Extract current session state

Defense: Forward Secrecy + Post-Compromise Security
Result: ⚠️ PARTIAL - Past messages protected, future messages until next ratchet step compromised
```

### Scenario 4: Server Compromise
```
Attacker: Compromised Server
Goal: Read all user messages
Attack: Full server access

Defense: End-to-end encryption
Result: ✅ ATTACK FAILED - Server only sees ciphertext
```

### Scenario 5: Malicious Server
```
Attacker: Malicious Server Operator
Goal: Impersonate user Alice to user Bob
Attack: Provide fake prekey bundle

Defense: Identity key verification
Result: ⚠️ DEPENDS - If users verified identity keys, attack fails. If not, MITM possible.
```

---

## 7. Residual Risks

### 7.1 Accepted Risks

| Risk | Mitigation | Acceptance Reason |
|------|------------|-------------------|
| Metadata leakage | Minimize what's sent | Protocol limitation |
| Device compromise | User responsibility | Cannot fix at protocol level |
| Zero-day in crypto libs | Use well-audited libs | Unavoidable |
| User verification errors | Clear UI for verification | UX challenge |

### 7.2 Known Limitations

1. **No Group Messaging Security** - Current implementation is 1:1 only
2. **No Forward Secrecy for First Message** - X3DH initial message uses static key
3. **Metadata Exposure** - Server sees communication graph
4. **No Plausible Deniability** - Messages are authenticate, not deniable

---

## 8. Security Requirements Checklist

### 8.1 Must Have (Critical)
- [x] All cryptographic operations use constant-time comparison
- [x] No .unwrap() in cryptographic code paths
- [x] Keys are zeroized after use
- [x] All inputs validated before processing
- [x] Replay protection implemented
- [x] Message authentication required

### 8.2 Should Have (Important)
- [ ] Hardware security module support
- [ ] Secure enclave integration
- [ ] Key rotation policies
- [ ] Session timeout mechanisms

### 8.3 Nice to Have (Future)
- [ ] Post-quantum key agreement
- [ ] Group messaging (MLS or Sender Keys)
- [ ] Deniable authentication
- [ ] Metadata protection (via mixnet)

---

## 9. Conclusion

Sibna Protocol v7 provides strong security against network-based attackers and server compromise. The main residual risks are:

1. **Endpoint security** - Depends on user device security
2. **Identity verification** - Requires user action
3. **Metadata exposure** - Architectural limitation

For most threat models, the protocol provides adequate protection. For high-threat environments, additional measures (hardware keys, verified boot, air-gapped devices) are recommended.

---

## Appendix A: Attack Tree

```
Goal: Read encrypted message content
│
├── Compromise endpoint (device)
│   ├── Steal unlocked device
│   ├── Install malware
│   ├── Memory extraction
│   └── Supply chain attack
│
├── Compromise keys
│   ├── Steal identity key
│   ├── Compromise prekey server
│   ├── Side-channel attack
│   └── Brute force (infeasible)
│
├── Exploit implementation
│   ├── Find bug in crypto code
│   ├── Timing attack
│   ├── Memory safety bug
│   └── Logic error in protocol
│
├── Social engineering
│   ├── Trick user into revealing key
│   ├── Impersonate contact
│   └── Phishing attack
│
└── Cryptographic attack (infeasible)
    ├── Break X25519
    ├── Break ChaCha20
    └── Break Poly1305
```

## Appendix B: References

- Signal Protocol Documentation: https://signal.org/docs/
- X3DH Specification: https://signal.org/docs/specifications/x3dh/
- Double Ratchet Specification: https://signal.org/docs/specifications/doubleratchet/
- NIST Cryptographic Standards: https://csrc.nist.gov/
