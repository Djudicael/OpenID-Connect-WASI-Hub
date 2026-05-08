//! # oidc-oidc
//!
//! OpenID Connect and OAuth2 endpoint handlers.

#![allow(missing_docs)]

pub mod endpoints;
pub mod flows;
pub mod state;
pub mod tokens;
pub mod validation;

pub use endpoints::discovery::discovery_handler;
pub use endpoints::jwks::jwks_handler;
