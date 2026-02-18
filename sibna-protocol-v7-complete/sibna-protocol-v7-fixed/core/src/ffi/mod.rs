//! Foreign Function Interface
//!
//! Provides C-compatible bindings for the Sibna protocol.

pub mod context;
pub mod session;
pub mod crypto;

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::panic;
use libc::{size_t, uint8_t};

use crate::{SecureContext, Config, ProtocolError};
use crate::ratchet::DoubleRatchetSession;
use crate::keystore::KeyStore;
use crate::crypto::{SecureRandom, Encryptor};

/// Opaque handle for SecureContext
#[repr(C)]
pub struct SecureContextHandle {
    context: *mut SecureContext,
}

/// Opaque handle for DoubleRatchetSession
#[repr(C)]
pub struct SecureSessionHandle {
    session: *mut DoubleRatchetSession,
}

/// Opaque handle for KeyStore
#[repr(C)]
pub struct SecureKeyStoreHandle {
    keystore: *mut KeyStore,
}

/// FFI Error Codes
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FFIError {
    /// Success
    Success = 0,
    /// Null pointer passed
    NullPointer = 1,
    /// Invalid argument
    InvalidArgument = 2,
    /// Encryption failed
    EncryptionFailed = 3,
    /// Decryption failed
    DecryptionFailed = 4,
    /// Session not found
    SessionNotFound = 5,
    /// Out of memory
    OutOfMemory = 6,
    /// Panic occurred
    Panic = 7,
    /// Key derivation failed
    KeyDerivationFailed = 8,
    /// Invalid state
    InvalidState = 9,
    /// Unknown error
    UnknownError = 255,
}

impl From<ProtocolError> for FFIError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidKeyLength => FFIError::InvalidArgument,
            ProtocolError::EncryptionFailed(_) => FFIError::EncryptionFailed,
            ProtocolError::DecryptionFailed(_) => FFIError::DecryptionFailed,
            ProtocolError::SessionNotFound => FFIError::SessionNotFound,
            ProtocolError::OutOfMemory => FFIError::OutOfMemory,
            ProtocolError::KeyDerivationFailed => FFIError::KeyDerivationFailed,
            ProtocolError::InvalidState(_) => FFIError::InvalidState,
            _ => FFIError::UnknownError,
        }
    }
}

/// Initialize the library
///
/// Must be called before any other FFI functions.
#[no_mangle]
pub extern "C" fn sibna_init() -> FFIError {
    // Set panic hook to avoid aborting the process
    panic::set_hook(Box::new(|info| {
        eprintln!("PANIC in sibna: {}", info);
    }));

    FFIError::Success
}

/// Free a buffer allocated by Rust
///
/// # Safety
/// The pointer must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn secure_free_buffer(ptr: *mut uint8_t, len: size_t) -> FFIError {
    if ptr.is_null() {
        return FFIError::NullPointer;
    }

    // Reconstruct the Vec and let it drop
    let slice = std::slice::from_raw_parts_mut(ptr, len);
    let _ = Vec::from_raw_parts(ptr, len, len);

    FFIError::Success
}
