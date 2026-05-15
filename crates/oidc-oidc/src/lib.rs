//! # oidc-oidc
//!
//! OpenID Connect and OAuth2 endpoint handlers.

#![allow(missing_docs)]
#![recursion_limit = "512"]

pub mod endpoints;
pub mod errors;
pub mod flows;
pub mod session_cookie;
pub mod state;
pub mod tokens;
pub mod validation;

pub use endpoints::discovery::{discovery_handler, realm_discovery_handler};
pub use endpoints::jwks::jwks_handler;
pub use endpoints::logout::logout_handler;
