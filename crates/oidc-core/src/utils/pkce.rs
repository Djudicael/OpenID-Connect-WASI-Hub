//! PKCE (RFC 7636) utilities.

use sha2::{Digest, Sha256};

/// Generate a random code verifier (128 chars, base64url).
/// The verifier is a high-entropy random string.
pub fn generate_code_verifier() -> String {
    let mut buf = [0u8; 96];
    getrandom::fill(&mut buf).expect("getrandom failed");
    base64_encode_url_safe_no_pad(&buf)
}

/// Compute the S256 code challenge from a verifier.
pub fn s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    base64_encode_url_safe_no_pad(&hash)
}

/// Verify a code verifier against a stored S256 code challenge.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    s256_challenge(verifier) == challenge
}

fn base64_encode_url_safe_no_pad(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_roundtrip() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 128);
        let challenge = s256_challenge(&verifier);
        assert!(verify_s256(&verifier, &challenge));
        assert!(!verify_s256("wrong", &challenge));
    }
}
