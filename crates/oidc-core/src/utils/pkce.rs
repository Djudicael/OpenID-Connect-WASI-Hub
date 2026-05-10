//! PKCE (RFC 7636) utilities.

use sha2::{Digest, Sha256};

use crate::OidcError;

/// Generate a random code verifier (128 chars, base64url).
/// The verifier is a high-entropy random string.
pub fn generate_code_verifier() -> Result<String, OidcError> {
    let mut buf = [0u8; 96];
    getrandom::fill(&mut buf)
        .map_err(|e| OidcError::Internal(format!("getrandom failed: {}", e)))?;
    Ok(base64_encode_url_safe_no_pad(&buf))
}

/// Compute the S256 code challenge from a verifier.
pub fn s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64_encode_url_safe_no_pad(&hash)
}

/// Verify a code verifier against a stored S256 code challenge.
/// Uses constant-time comparison to prevent timing side-channels.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    let expected = s256_challenge(verifier);
    constant_time_eq(expected.as_bytes(), challenge.as_bytes())
}

/// Constant-time comparison of two byte slices.
/// Returns true if the slices are equal, false otherwise.
/// The comparison time is independent of the content of the slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn base64_encode_url_safe_no_pad(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_roundtrip() {
        let verifier = generate_code_verifier().unwrap();
        assert_eq!(verifier.len(), 128);
        let challenge = s256_challenge(&verifier);
        assert!(verify_s256(&verifier, &challenge));
        assert!(!verify_s256("wrong", &challenge));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hella"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_pkce_verifier_length() {
        let verifier = generate_code_verifier().unwrap();
        assert_eq!(
            verifier.len(),
            128,
            "code verifier should be 128 characters"
        );
    }

    #[test]
    fn test_pkce_challenge_length() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = s256_challenge(&verifier);
        // SHA-256 = 256 bits; base64url no-pad = ceil(256/6) = 43 chars
        assert_eq!(
            challenge.len(),
            43,
            "S256 challenge should be 43 base64url chars"
        );
    }

    #[test]
    fn test_pkce_wrong_verifier() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = s256_challenge(&verifier);
        assert!(!verify_s256("wrong_verifier", &challenge));
    }

    #[test]
    fn test_pkce_empty_verifier() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = s256_challenge(&verifier);
        assert!(!verify_s256("", &challenge));
    }
}
