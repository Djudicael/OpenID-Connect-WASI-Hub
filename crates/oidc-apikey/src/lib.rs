//! # oidc-apikey
//!
//! API key generation, validation, and management.

#![allow(missing_docs)]

pub mod auth;
pub mod endpoints;
pub mod hashing;
pub mod models;
pub mod service;

pub use auth::{ApiKeyAuth, ApiKeyError, ApiKeyVerifierState, has_scope, require_scope};
pub use models::{CreateKeyRequest, CreateKeyResponse, ListKeysQuery, RotateKeyResponse};
pub use service::ApiKeyService;
