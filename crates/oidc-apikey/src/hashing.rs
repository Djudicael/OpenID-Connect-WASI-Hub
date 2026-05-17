//! API key hashing utilities.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use oidc_core::errors::OidcError;

/// Hash an API key secret using Argon2id.
pub fn hash_secret(secret: &str) -> Result<String, OidcError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| OidcError::Internal(e.to_string()))
}

/// Verify an API key secret against a hash.
pub fn verify_secret(secret: &str, hash: &str) -> Result<bool, OidcError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| OidcError::Internal(e.to_string()))?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(secret.as_bytes(), &parsed_hash)
        .is_ok())
}
