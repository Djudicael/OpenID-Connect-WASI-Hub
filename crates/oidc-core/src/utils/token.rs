//! Token generation and hashing utilities.

use sha2::{Digest, Sha256};

/// Generate a cryptographically random opaque token.
/// Returns a 256-bit (32 byte) value base64url-encoded.
pub fn generate_opaque_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("getrandom failed");
    base64_encode_url_safe_no_pad(&buf)
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
        let t1 = generate_opaque_token();
        let t2 = generate_opaque_token();
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
}
