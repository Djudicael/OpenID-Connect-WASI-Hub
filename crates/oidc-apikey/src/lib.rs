//! # oidc-apikey
//!
//! API key generation, validation, and management.

#![allow(missing_docs)]

pub mod auth;
pub mod endpoints;
pub mod hashing;
pub mod models;
pub mod service;

pub use auth::{
    ApiKeyAuth, ApiKeyError, ApiKeyVerifierState, ApiRouteAuth, extract_raw_key_from_headers,
    has_scope, require_scope, verify_request_auth,
};
pub use models::{CreateKeyRequest, CreateKeyResponse, ListKeysQuery, RotateKeyResponse};
pub use service::ApiKeyService;
