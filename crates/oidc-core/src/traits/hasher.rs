use crate::errors::OidcError;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;

/// Abstract password/API-key hasher.
pub trait Hasher: Send + Sync {
    /// Hash a plaintext secret.
    fn hash(&self, plaintext: &str) -> Result<String, OidcError>;

    /// Verify a plaintext secret against a stored hash.
    fn verify(&self, plaintext: &str, hash: &str) -> Result<bool, OidcError>;
}

/// Production-grade Argon2id password/API-key hasher.
pub struct Argon2idHasher {
    inner: Argon2<'static>,
}

impl Default for Argon2idHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Argon2idHasher {
    /// Create a new hasher with default parameters.
    /// Uses m=64MB, t=3, p=1 for a balance of security and speed (~10ms).
    pub fn new() -> Self {
        Self {
            inner: Argon2::default(),
        }
    }
}

impl Hasher for Argon2idHasher {
    fn hash(&self, plaintext: &str) -> Result<String, OidcError> {
        let salt = SaltString::generate(&mut OsRng);
        self.inner
            .hash_password(plaintext.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| OidcError::Internal(format!("hashing failed: {e}")))
    }

    fn verify(&self, plaintext: &str, hash: &str) -> Result<bool, OidcError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| OidcError::Internal(format!("invalid hash: {e}")))?;
        Ok(self
            .inner
            .verify_password(plaintext.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_hash_and_verify() {
        let hasher = Argon2idHasher::new();
        let password = "SuperSecret123!";
        let hash = hasher.hash(password).unwrap();
        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong", &hash).unwrap());
    }

    #[test]
    fn test_argon2id_empty_password() {
        let hasher = Argon2idHasher::new();
        let hash = hasher.hash("").unwrap();
        assert!(hasher.verify("", &hash).unwrap());
    }
}
