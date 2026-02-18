//! Crypto FFI Functions

use super::*;
use std::slice;

/// Generate a new X25519 key pair
///
/// # Safety
/// Both public_key and private_key must be valid pointers to 32-byte buffers
#[no_mangle]
pub unsafe extern "C" fn secure_generate_keypair(
    public_key: *mut uint8_t,
    private_key: *mut uint8_t,
) -> FFIError {
    if public_key.is_null() || private_key.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        use x25519_dalek::{StaticSecret, PublicKey};
        use rand_core::OsRng;

        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);

        std::ptr::copy_nonoverlapping(secret.to_bytes().as_ptr(), private_key, 32);
        std::ptr::copy_nonoverlapping(public.as_bytes().as_ptr(), public_key, 32);

        FFIError::Success
    });

    result.unwrap_or(FFIError::UnknownError)
}

/// Generate random bytes
///
/// # Safety
/// buffer must be a valid pointer with at least len bytes
#[no_mangle]
pub unsafe extern "C" fn secure_random_bytes(
    buffer: *mut uint8_t,
    len: size_t,
) -> FFIError {
    if buffer.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        let mut rng = match SecureRandom::new() {
            Ok(r) => r,
            Err(_) => return FFIError::UnknownError,
        };

        let buf_slice = slice::from_raw_parts_mut(buffer, len);
        rng.fill_bytes(buf_slice);

        FFIError::Success
    });

    result.unwrap_or(FFIError::UnknownError)
}
