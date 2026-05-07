//! # oidc-core
//!
//! Domain models, traits, and pure business logic for the OpenID Connect WASI Hub.
//! Zero I/O. Zero framework dependencies.

// missing_docs lint triggers an ICE in rustc 1.95.0; re-enable when fixed.
#![allow(missing_docs)]

pub mod errors;
pub mod models;
pub mod traits;
pub mod utils;

/// Re-export core types for convenience.
pub use errors::OidcError;
