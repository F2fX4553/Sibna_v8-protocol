//! Secure Random Number Generation
//!
//! Provides cryptographically secure random number generation using the OS RNG.

use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;
use super::{CryptoError, CryptoResult};

/// Secure Random Number Generator
///
/// Wraps the operating system's cryptographically secure RNG.
/// All sensitive data is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureRandom {
    #[zeroize(skip)]
    inner: rand_core::OsRng,
}

impl SecureRandom {
    /// Create a new secure random generator
    ///
    /// # Returns
    /// A new SecureRandom instance
    pub fn new() -> CryptoResult<Self> {
        Ok(Self {
            inner: rand_core::OsRng,
        })
    }

    /// Fill a byte slice with random bytes
    ///
    /// # Arguments
    /// * `dest` - Destination buffer to fill
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    /// Generate a random u32
    pub fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    /// Generate a random u64
    pub fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    /// Generate a random byte array
    ///
    /// # Returns
    /// A fixed-size array of random bytes
    pub fn gen_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut arr = [0u8; N];
        self.fill_bytes(&mut arr);
        arr
    }

    /// Generate a random value in a range
    ///
    /// # Arguments
    /// * `min` - Minimum value (inclusive)
    /// * `max` - Maximum value (exclusive)
    pub fn gen_range(&mut self, min: u64, max: u64) -> u64 {
        rand::Rng::gen_range(&mut self.inner, min..max)
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new().expect("Failed to create SecureRandom")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let mut rng = SecureRandom::new().unwrap();
        let bytes1 = rng.gen_bytes::<32>();
        let bytes2 = rng.gen_bytes::<32>();

        // Extremely unlikely to be equal
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_fill_bytes() {
        let mut rng = SecureRandom::new().unwrap();
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);

        // Check not all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }
}
