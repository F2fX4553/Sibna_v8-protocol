//! Session FFI Functions

use super::*;
use std::slice;
use std::sync::Arc;
use parking_lot::RwLock;

/// Free a session handle
///
/// # Safety
/// handle must be a valid pointer created by secure_session_create
#[no_mangle]
pub unsafe extern "C" fn secure_session_free(handle: *mut SecureSessionHandle) -> FFIError {
    if handle.is_null() {
        return FFIError::NullPointer;
    }

    let handle = Box::from_raw(handle);
    if !handle.session.is_null() {
        // Reconstruct Arc to properly drop
        let _ = Arc::from_raw(handle.session as *const RwLock<DoubleRatchetSession>);
    }

    FFIError::Success
}

/// Encrypt a message using a session
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn secure_session_encrypt(
    session: *mut SecureSessionHandle,
    plaintext: *const uint8_t,
    plaintext_len: size_t,
    ciphertext: *mut *mut uint8_t,
    ciphertext_len: *mut size_t,
) -> FFIError {
    if session.is_null() || plaintext.is_null() || ciphertext.is_null() || ciphertext_len.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        let session_handle = &*session;
        let session_ptr = session_handle.session as *const RwLock<DoubleRatchetSession>;

        let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);

        // Reconstruct Arc temporarily
        let arc = Arc::from_raw(session_ptr);
        let mut guard = arc.write();
        let result = guard.encrypt(plaintext_slice, &[]);

        // Release and restore
        drop(guard);
        let _ = Arc::into_raw(arc);

        match result {
            Ok(encrypted) => {
                let mut boxed = encrypted.into_boxed_slice();
                let len = boxed.len();
                let ptr = boxed.as_mut_ptr();

                *ciphertext = ptr;
                *ciphertext_len = len;

                std::mem::forget(boxed);
                FFIError::Success
            }
            Err(e) => FFIError::from(e),
        }
    });

    result.unwrap_or(FFIError::UnknownError)
}

/// Decrypt a message using a session
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn secure_session_decrypt(
    session: *mut SecureSessionHandle,
    ciphertext: *const uint8_t,
    ciphertext_len: size_t,
    plaintext: *mut *mut uint8_t,
    plaintext_len: *mut size_t,
) -> FFIError {
    if session.is_null() || ciphertext.is_null() || plaintext.is_null() || plaintext_len.is_null() {
        return FFIError::NullPointer;
    }

    let result = panic::catch_unwind(|| {
        let session_handle = &*session;
        let session_ptr = session_handle.session as *const RwLock<DoubleRatchetSession>;

        let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);

        // Reconstruct Arc temporarily
        let arc = Arc::from_raw(session_ptr);
        let mut guard = arc.write();
        let result = guard.decrypt(ciphertext_slice, &[]);

        // Release and restore
        drop(guard);
        let _ = Arc::into_raw(arc);

        match result {
            Ok(decrypted) => {
                let mut boxed = decrypted.into_boxed_slice();
                let len = boxed.len();
                let ptr = boxed.as_mut_ptr();

                *plaintext = ptr;
                *plaintext_len = len;

                std::mem::forget(boxed);
                FFIError::Success
            }
            Err(e) => FFIError::from(e),
        }
    });

    result.unwrap_or(FFIError::UnknownError)
}
