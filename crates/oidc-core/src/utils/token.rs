//! Token generation and hashing utilities.

use sha2::{Digest, Sha256};

use crate::OidcError;

/// Generate a cryptographically random opaque token.
/// Returns a 256-bit (32 byte) value base64url-encoded.
pub fn generate_opaque_token() -> Result<String, OidcError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)
        .map_err(|e| OidcError::Internal(format!("getrandom failed: {}", e)))?;
    Ok(base64_encode_url_safe_no_pad(&buf))
}

/// Compute SHA-256 hash and return as hex string.
pub fn sha2_256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute `at_hash` (access token hash) for ID token.
/// Per OIDC Core: hash the access token, keep left half.
pub fn compute_at_hash(access_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let hash = hasher.finalize();
    // Left half of hash
    let left = &hash[..hash.len() / 2];
    base64_encode_url_safe_no_pad(left)
}

/// Compute `c_hash` (authorization code hash) for ID token.
/// Per OIDC Core: hash the code, keep left half.
pub fn compute_c_hash(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    let hash = hasher.finalize();
    let left = &hash[..hash.len() / 2];
    base64_encode_url_safe_no_pad(left)
}

fn base64_encode_url_safe_no_pad(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_opaque_token() {
        let t1 = generate_opaque_token().unwrap();
        let t2 = generate_opaque_token().unwrap();
        assert_ne!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn test_sha2_256_hex() {
        let h = sha2_256_hex("hello");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_at_hash() {
        let h = compute_at_hash("test_access_token");
        assert!(!h.is_empty());
    }

    #[test]
    fn test_c_hash() {
        let h = compute_c_hash("test_code");
        assert!(!h.is_empty());
    }

    #[test]
    fn test_opaque_token_uniqueness() {
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..100 {
            let token = generate_opaque_token().unwrap();
            assert!(tokens.insert(token), "duplicate token generated");
        }
        assert_eq!(tokens.len(), 100);
    }

    #[test]
    fn test_sha2_256_hex_known_value() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let h = sha2_256_hex("hello");
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_at_hash_deterministic() {
        let h1 = compute_at_hash("access_token_123");
        let h2 = compute_at_hash("access_token_123");
        assert_eq!(h1, h2, "at_hash should be deterministic for same input");
    }

    #[test]
    fn test_c_hash_deterministic() {
        let h1 = compute_c_hash("auth_code_456");
        let h2 = compute_c_hash("auth_code_456");
        assert_eq!(h1, h2, "c_hash should be deterministic for same input");
    }
}
