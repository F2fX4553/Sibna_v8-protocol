//! Safety Numbers and Identity Verification
//!
//! Implements safety number calculation for identity verification.
//! Safety numbers allow users to verify each other's identity keys
//! through an out-of-band channel (QR code, voice, etc.).

use sha2::{Sha256, Digest};
use std::fmt;

/// Safety Number - A human-readable fingerprint for identity verification
///
/// The safety number is derived from both parties' identity keys and
/// provides a way to detect MITM attacks during initial key exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// The 60-digit safety number (displayed in groups of 5)
    digits: String,
    /// The raw 32-byte fingerprint
    fingerprint: [u8; 32],
}

impl SafetyNumber {
    /// Calculate safety number from two identity keys
    ///
    /// # Arguments
    /// * `our_identity` - Our X25519 public key (32 bytes)
    /// * `their_identity` - Their X25519 public key (32 bytes)
    ///
    /// # Returns
    /// A SafetyNumber that can be displayed to users
    pub fn calculate(our_identity: &[u8; 32], their_identity: &[u8; 32]) -> Self {
        // Sort keys lexicographically for consistent ordering
        let (first, second) = if our_identity < their_identity {
            (our_identity, their_identity)
        } else {
            (their_identity, our_identity)
        };

        // Hash both keys together
        let mut hasher = Sha256::new();
        hasher.update(b"SIBNA_SAFETY_NUMBER_V1");
        hasher.update(first);
        hasher.update(second);
        let result = hasher.finalize();
        
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&result);

        // Convert to 60 decimal digits
        let digits = Self::bytes_to_digits(&fingerprint);

        Self { digits, fingerprint }
    }

    /// Convert 32 bytes to 60 decimal digits
    fn bytes_to_digits(bytes: &[u8; 32]) -> String {
        // Use the bytes as a large number and convert to decimal digits
        // We'll use a simpler approach: convert each pair of bytes to 3 digits
        
        let mut digits = String::with_capacity(60);
        
        for chunk in bytes.chunks(2) {
            let value = if chunk.len() == 2 {
                ((chunk[0] as u32) << 8) | (chunk[1] as u32)
            } else {
                chunk[0] as u32 * 256
            };
            
            // Each chunk becomes 5 digits (65535 max)
            let chunk_digits = format!("{:05}", value % 100000);
            digits.push_str(&chunk_digits);
        }
        
        // Take exactly 60 digits
        let result: String = digits.chars().take(60).collect();
        
        // Format with spaces every 5 digits
        let mut formatted = String::with_capacity(72);
        for (i, c) in result.chars().enumerate() {
            if i > 0 && i % 5 == 0 {
                formatted.push(' ');
            }
            formatted.push(c);
        }
        
        formatted
    }

    /// Get the safety number as a formatted string (XXXXX XXXXX XXXXX...)
    pub fn as_string(&self) -> &str {
        &self.digits
    }

    /// Get the raw fingerprint bytes
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Get QR code data (encoded version of the safety number)
    pub fn qr_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(34);
        data.extend_from_slice(b"SB1"); // Sibna v1 prefix
        data.extend_from_slice(&self.fingerprint);
        data
    }

    /// Parse safety number from string
    pub fn parse(s: &str) -> Option<Self> {
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits.len() != 60 {
            return None;
        }

        // Reverse the digit-to-bytes conversion
        let mut fingerprint = [0u8; 32];
        
        for (i, chunk) in digits.as_bytes().chunks(5).enumerate() {
            if i >= 16 {
                break;
            }
            
            let chunk_str = std::str::from_utf8(chunk).ok()?;
            let value: u32 = chunk_str.parse().ok()?;
            
            fingerprint[i * 2] = ((value / 256) % 256) as u8;
            fingerprint[i * 2 + 1] = (value % 256) as u8;
        }

        Some(Self {
            digits: Self::bytes_to_digits(&fingerprint),
            fingerprint,
        })
    }

    /// Verify if another safety number matches
    pub fn verify(&self, other: &SafetyNumber) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.digits)
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({})", self.digits)
    }
}

/// QR Code data for identity verification
#[derive(Clone)]
pub struct VerificationQrCode {
    /// Version byte
    version: u8,
    /// Our identity key
    identity_key: [u8; 32],
    /// Our device ID
    device_id: [u8; 16],
    /// Safety number fingerprint
    safety_fingerprint: [u8; 32],
}

impl VerificationQrCode {
    /// Create a new verification QR code
    pub fn new(
        identity_key: [u8; 32],
        device_id: [u8; 16],
        safety_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            version: 1,
            identity_key,
            device_id,
            safety_fingerprint,
        }
    }

    /// Encode to bytes for QR code generation
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(82);
        data.push(self.version);
        data.extend_from_slice(b"SIBNA"); // Magic bytes
        data.extend_from_slice(&self.identity_key);
        data.extend_from_slice(&self.device_id);
        data.extend_from_slice(&self.safety_fingerprint);
        
        // Add simple checksum
        let checksum: u8 = data.iter().skip(1).fold(0u8, |acc, &b| acc.wrapping_add(b));
        data.push(checksum);
        
        data
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != 82 {
            return None;
        }

        let version = data[0];
        if version != 1 {
            return None;
        }

        // Verify magic bytes
        if &data[1..6] != b"SIBNA" {
            return None;
        }

        // Verify checksum
        let expected_checksum: u8 = data[..81].iter().skip(1).fold(0u8, |acc, &b| acc.wrapping_add(b));
        if data[81] != expected_checksum {
            return None;
        }

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&data[6..38]);

        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&data[38..54]);

        let mut safety_fingerprint = [0u8; 32];
        safety_fingerprint.copy_from_slice(&data[54..86]);

        Some(Self {
            version,
            identity_key,
            device_id,
            safety_fingerprint,
        })
    }

    /// Get the identity key
    pub fn identity_key(&self) -> &[u8; 32] {
        &self.identity_key
    }

    /// Get the device ID
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_calculation() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn1 = SafetyNumber::calculate(&key1, &key2);
        let sn2 = SafetyNumber::calculate(&key2, &key1);

        // Order shouldn't matter
        assert_eq!(sn1, sn2);
        assert!(sn1.verify(&sn2));
    }

    #[test]
    fn test_safety_number_format() {
        let key1 = [0x42u8; 32];
        let key2 = [0x24u8; 32];

        let sn = SafetyNumber::calculate(&key1, &key2);
        let display = sn.as_string();

        // Should have spaces every 5 digits
        assert_eq!(display.len(), 71); // 60 digits + 11 spaces
        
        // Should only contain digits and spaces
        for c in display.chars() {
            assert!(c.is_ascii_digit() || c == ' ');
        }
    }

    #[test]
    fn test_qr_code_roundtrip() {
        let identity_key = [0x42u8; 32];
        let device_id = [0x01u8; 16];
        let fingerprint = [0xABu8; 32];

        let qr = VerificationQrCode::new(identity_key, device_id, fingerprint);
        let bytes = qr.to_bytes();
        
        let parsed = VerificationQrCode::from_bytes(&bytes).unwrap();
        
        assert_eq!(qr.identity_key, parsed.identity_key);
        assert_eq!(qr.device_id, parsed.device_id);
    }

    #[test]
    fn test_qr_code_tamper_detection() {
        let identity_key = [0x42u8; 32];
        let device_id = [0x01u8; 16];
        let fingerprint = [0xABu8; 32];

        let qr = VerificationQrCode::new(identity_key, device_id, fingerprint);
        let mut bytes = qr.to_bytes();
        
        // Tamper with the data
        bytes[10] ^= 0xFF;
        
        assert!(VerificationQrCode::from_bytes(&bytes).is_none());
    }
}
