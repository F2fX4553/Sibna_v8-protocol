# Security Policy

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 7.x     | ✅ Active development | Current |
| < 7.0   | ❌ Not supported   | Legacy |

---

## Reporting a Vulnerability

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues by:

1. **Email**: security@example.com (replace with your actual email)
2. **Encrypted Email**: Use our PGP key (see below)

### What to Include

Please provide:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Fix Development | Within 30 days (critical), 90 days (others) |
| Disclosure | After fix is released |

---

## Security Standards

### What We Protect Against

✅ **Network Attackers**
- Passive eavesdropping
- Active man-in-the-middle
- Replay attacks

✅ **Server Compromise**
- Message content remains encrypted
- Session keys never stored on server

✅ **Key Compromise**
- Forward secrecy protects past messages
- Post-compromise security recovers session

### What We Cannot Protect Against

❌ **Endpoint Compromise**
- Malware on user device
- Physical device theft (unlocked)

❌ **Metadata Analysis**
- Server sees who communicates with whom

❌ **Social Engineering**
- Users sharing keys manually

---

## Security Features

### Cryptographic Primitives

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| Key Exchange | X3DH (X25519) | 256-bit |
| Key Ratchet | Double Ratchet | 256-bit |
| Encryption | ChaCha20-Poly1305 | 256-bit |
| KDF | HKDF-Blake3 | 256-bit |
| Signatures | Ed25519 | 256-bit |

### Security Properties

- **Forward Secrecy**: Each message uses unique keys
- **Post-Compromise Security**: Session heals after compromise
- **Authentication**: Messages authenticated via X3DH
- **Integrity**: AEAD encryption prevents tampering

---

## Bug Bounty Program

### Scope

**In Scope:**
- Core protocol implementation (`core/src/`)
- FFI bindings (`core/src/ffi/`)
- SDKs (Python, JavaScript, Dart, C++)

**Out of Scope:**
- Third-party dependencies
- Social engineering attacks
- Physical attacks

### Rewards

| Severity | Reward |
|----------|--------|
| Critical | $1,000 - $5,000 |
| High | $500 - $1,000 |
| Medium | $100 - $500 |
| Low | $50 - $100 |

*Note: Rewards are currently symbolic until funding is secured.*

---

## Security Best Practices for Users

### Key Verification

Always verify identity keys with your contacts:

```
1. Get your safety number
2. Share it with contact through different channel
3. Compare numbers match
4. Mark contact as verified
```

### Secure Storage

- Never share your identity private key
- Use secure storage (keychain, hardware key)
- Enable device encryption

### Session Management

- Re-key periodically for sensitive conversations
- Delete old sessions when done
- Report suspicious activity

---

## Security Audits

### Completed Audits

| Date | Auditor | Scope | Result |
|------|---------|-------|--------|
| 2024 | Self-audit | Protocol design | Pass |
| - | Pending | External review | - |

### Planned Audits

- [ ] External cryptographic review
- [ ] Code audit by security firm
- [ ] Formal verification of critical components

---

## Security Changelog

### Version 7.0

- Fixed: Removed unsafe `.unwrap()` in production code
- Fixed: Added proper error handling in SessionManager
- Added: Memory zeroization for sensitive keys
- Added: Constant-time comparison for crypto operations
- Added: Input validation in FFI layer

---

## PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Insert your PGP public key here]
-----END PGP PUBLIC KEY BLOCK-----
```

*Key ID: [To be generated]*
*Fingerprint: [To be generated]*

---

## Contact

For security concerns:
- **Email**: security@example.com
- **Response Time**: 48 hours maximum

For general questions:
- **GitHub Issues**: For bugs and features (not security issues)
- **Discussions**: For general questions

---

## Disclosure Policy

We follow **responsible disclosure**:

1. Reporter discloses privately
2. We develop fix
3. Fix is tested and released
4. CVE is requested (if applicable)
5. Public disclosure after 90 days or fix release

We credit researchers who report valid issues (with permission).

---

## Threat Model Summary

For detailed threat model, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**Quick Reference:**

| Attacker | Protected |
|----------|-----------|
| Network (passive) | ✅ Yes |
| Network (active/MITM) | ✅ Yes |
| Compromised Server | ✅ Yes |
| Device Thief | ⚠️ Partial (forward secrecy) |
| Memory Extractor | ⚠️ Partial (zeroization) |
| State-Level | ⚠️ Limited |

---

Last Updated: 2024
