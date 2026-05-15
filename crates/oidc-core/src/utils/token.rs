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

/// Generate a cryptographically random OIDC Session ID (`sid`).
/// Returns a 128-bit (16 byte) value hex-encoded (32 chars).
/// Per OIDC Session Management, this is an opaque string used in
/// ID tokens (`sid` claim) and logout tokens.
pub fn generate_sid() -> Result<String, OidcError> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf)
        .map_err(|e| OidcError::Internal(format!("getrandom failed: {}", e)))?;
    Ok(hex::encode(buf))
}

/// Compute `session_state` per OIDC Session Management §3.
///
/// The session state value is: `SHA256(client_id + " " + OP browser session ID + " " + origin)`
/// base64url-encoded (no padding).
///
/// - `client_id`: The OAuth2 client_id of the RP.
/// - `op_browser_session_id`: The OP's browser session ID (our `sid` value).
/// - `origin`: The scheme + host + port of the RP's redirect URI origin.
///
/// The RP computes the same value locally and compares to detect session changes.
pub fn compute_session_state(client_id: &str, op_browser_session_id: &str, origin: &str) -> String {
    let input = format!("{} {} {}", client_id, op_browser_session_id, origin);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    base64_encode_url_safe_no_pad(&hash)
}

/// Extract the origin (scheme + host + port) from a URL string.
/// Per OIDC Session Management §3, the origin is the scheme, host, and port
/// of the RP's redirect URI, used in `session_state` computation.
///
/// Returns `None` if the URL cannot be parsed.
pub fn extract_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let scheme = parsed.scheme();
    let host = parsed.host_str()?;
    let port = parsed.port();
    Some(if let Some(p) = port {
        format!("{}://{}:{}", scheme, host, p)
    } else {
        format!("{}://{}", scheme, host)
    })
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

/// Compute a pairwise subject identifier per OIDC Core §8.1.
///
/// The pairwise `sub` value is: `Base64url(SHA-256(user_id + "|" + sector_identifier + "|" + salt))`
/// where:
/// - `user_id` is the user's unique identifier
/// - `sector_identifier` is the sector identifier for the client
/// - `salt` is a stable salt value (per-OP or per-realm)
///
/// This produces a different `sub` value for each sector, preventing correlation
/// of the same user across different RPs.
pub fn compute_pairwise_sub(user_id: &str, sector_identifier: &str, salt: &str) -> String {
    let input = format!("{}|{}|{}", user_id, sector_identifier, salt);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    base64_encode_url_safe_no_pad(&hash)
}

/// Extract the sector identifier from a client's configuration.
///
/// Per OIDC Core §8.1:
/// - If `sector_identifier_uri` is set, use its host as the sector identifier
/// - Otherwise, use the host of the first `redirect_uri`
///
/// Returns `None` if no valid URL can be found.
pub fn extract_sector_identifier(
    sector_identifier_uri: Option<&str>,
    redirect_uris: &[String],
) -> Option<String> {
    if let Some(uri) = sector_identifier_uri {
        let parsed = url::Url::parse(uri).ok()?;
        parsed.host_str().map(|h| h.to_string())
    } else {
        let first = redirect_uris.first()?;
        let parsed = url::Url::parse(first).ok()?;
        parsed.host_str().map(|h| h.to_string())
    }
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

    #[test]
    fn test_generate_sid() {
        let s1 = generate_sid().unwrap();
        let s2 = generate_sid().unwrap();
        assert_ne!(s1, s2, "sid values should be unique");
        assert_eq!(s1.len(), 32, "sid should be 32 hex chars (16 bytes)");
    }

    #[test]
    fn test_compute_session_state() {
        let state = compute_session_state("my-client", "abc123", "https://example.com");
        assert!(!state.is_empty());
        // Same inputs should produce same output
        let state2 = compute_session_state("my-client", "abc123", "https://example.com");
        assert_eq!(state, state2);
    }

    #[test]
    fn test_compute_session_state_different_inputs() {
        let s1 = compute_session_state("client-a", "sid1", "https://example.com");
        let s2 = compute_session_state("client-b", "sid1", "https://example.com");
        let s3 = compute_session_state("client-a", "sid2", "https://example.com");
        assert_ne!(s1, s2, "different client_id should produce different state");
        assert_ne!(s1, s3, "different sid should produce different state");
    }

    #[test]
    fn test_extract_origin_https() {
        let origin = extract_origin("https://example.com/callback").unwrap();
        assert_eq!(origin, "https://example.com");
    }

    #[test]
    fn test_extract_origin_with_port() {
        let origin = extract_origin("https://example.com:8443/callback").unwrap();
        assert_eq!(origin, "https://example.com:8443");
    }

    #[test]
    fn test_extract_origin_localhost() {
        let origin = extract_origin("http://localhost:3000/callback").unwrap();
        assert_eq!(origin, "http://localhost:3000");
    }

    #[test]
    fn test_extract_origin_invalid_url() {
        assert!(extract_origin("not-a-url").is_none());
    }

    #[test]
    fn test_extract_origin_no_path() {
        let origin = extract_origin("https://example.com").unwrap();
        assert_eq!(origin, "https://example.com");
    }

    #[test]
    fn test_compute_pairwise_sub_deterministic() {
        let sub1 = compute_pairwise_sub("user-123", "example.com", "salt-value");
        let sub2 = compute_pairwise_sub("user-123", "example.com", "salt-value");
        assert_eq!(
            sub1, sub2,
            "pairwise sub should be deterministic for same inputs"
        );
    }

    #[test]
    fn test_compute_pairwise_sub_different_sectors() {
        let sub1 = compute_pairwise_sub("user-123", "sector-a.com", "salt-value");
        let sub2 = compute_pairwise_sub("user-123", "sector-b.com", "salt-value");
        assert_ne!(
            sub1, sub2,
            "different sectors should produce different sub values"
        );
    }

    #[test]
    fn test_compute_pairwise_sub_different_users() {
        let sub1 = compute_pairwise_sub("user-123", "example.com", "salt-value");
        let sub2 = compute_pairwise_sub("user-456", "example.com", "salt-value");
        assert_ne!(
            sub1, sub2,
            "different users should produce different sub values"
        );
    }

    #[test]
    fn test_compute_pairwise_sub_different_salts() {
        let sub1 = compute_pairwise_sub("user-123", "example.com", "salt-a");
        let sub2 = compute_pairwise_sub("user-123", "example.com", "salt-b");
        assert_ne!(
            sub1, sub2,
            "different salts should produce different sub values"
        );
    }

    #[test]
    fn test_compute_pairwise_sub_output_format() {
        let sub = compute_pairwise_sub("user-123", "example.com", "salt-value");
        // SHA-256 produces 32 bytes, base64url no-pad = 43 chars
        assert_eq!(sub.len(), 43, "SHA-256 base64url no-pad should be 43 chars");
        assert!(
            sub.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "sub should be base64url no-pad"
        );
    }

    #[test]
    fn test_extract_sector_identifier_from_redirect_uri() {
        let sector = extract_sector_identifier(None, &vec!["https://example.com/callback".into()]);
        assert_eq!(sector, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sector_identifier_from_sector_uri() {
        let sector = extract_sector_identifier(
            Some("https://sector.example.com"),
            &vec!["https://other.com/callback".into()],
        );
        assert_eq!(sector, Some("sector.example.com".to_string()));
    }

    #[test]
    fn test_extract_sector_identifier_sector_uri_takes_precedence() {
        let sector = extract_sector_identifier(
            Some("https://sector.example.com"),
            &vec!["https://other.com/callback".into()],
        );
        // sector_identifier_uri should take precedence over redirect_uri
        assert_eq!(sector, Some("sector.example.com".to_string()));
    }

    #[test]
    fn test_extract_sector_identifier_empty_redirect_uris() {
        let sector = extract_sector_identifier(None, &vec![]);
        assert_eq!(sector, None);
    }

    #[test]
    fn test_extract_sector_identifier_invalid_url() {
        let sector = extract_sector_identifier(None, &vec!["not-a-url".into()]);
        assert_eq!(sector, None);
    }

    #[test]
    fn test_extract_sector_identifier_with_port() {
        let sector =
            extract_sector_identifier(None, &vec!["https://example.com:8443/callback".into()]);
        assert_eq!(sector, Some("example.com".to_string()));
    }
}
