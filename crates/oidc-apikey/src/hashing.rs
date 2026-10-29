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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_secret_roundtrip_verifies_successfully() {
        let hash = hash_secret("test-secret").expect("hashing should succeed");

        let verified = verify_secret("test-secret", &hash).expect("verification should succeed");

        assert!(
            verified,
            "the original secret should verify against its hash"
        );
    }

    #[test]
    fn verify_secret_rejects_wrong_secret() {
        let hash = hash_secret("test-secret").expect("hashing should succeed");

        let verified = verify_secret("wrong-secret", &hash).expect("verification should succeed");

        assert!(!verified, "a different secret must not verify");
    }

    #[test]
    fn verify_secret_rejects_same_length_mutations_at_every_position() {
        let secret = "oidc_prod.abcd1234.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl";
        let hash = hash_secret(secret).expect("hashing should succeed");
        let secret_offset = secret.rfind('.').unwrap() + 1;

        for index in secret_offset..secret.len() {
            let mut altered = secret.as_bytes().to_vec();
            altered[index] = if altered[index] == b'a' { b'b' } else { b'a' };
            let altered = String::from_utf8(altered).unwrap();
            assert!(
                !verify_secret(&altered, &hash).expect("verification should succeed"),
                "a secret altered at position {index} must be rejected"
            );
        }
    }

    #[test]
    fn verify_secret_rejects_malformed_hash() {
        let err = verify_secret("test-secret", "not-a-password-hash")
            .expect_err("malformed hashes should be rejected");

        assert!(matches!(err, OidcError::Internal(_)));
    }
}
