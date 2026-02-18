//! Double Ratchet Implementation
//!
//! This module implements the Double Ratchet algorithm as specified in:
//! https://signal.org/docs/specifications/doubleratchet/
//!
//! # Features
//! - Forward secrecy through DH ratchet
//! - Post-compromise security through symmetric ratchet
//! - Out-of-order message handling

mod chain;
mod state;
mod session;

pub use chain::*;
pub use state::*;
pub use session::*;

use x25519_dalek::{PublicKey, StaticSecret};
use std::collections::HashMap;
use crate::error::{ProtocolError, ProtocolResult};
