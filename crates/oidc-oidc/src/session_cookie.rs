//! Session cookie management for browser-based SSO.
//!
//! The session cookie value is HMAC-protected to prevent session fixation:
//! `session_id.hmac_hex`. The HMAC is verified on every request using
//! constant-time comparison (`subtle::ConstantTimeEq`).

use axum::http::HeaderMap;
use axum::http::header::{COOKIE, SET_COOKIE};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Cookie name used for the OIDC session.
pub const SESSION_COOKIE_NAME: &str = "oidc_session";

/// Maximum age of the session cookie in seconds (24 hours).
const SESSION_COOKIE_MAX_AGE: &str = "86400";

type HmacSha256 = Hmac<Sha256>;

/// Create a secure session cookie value.
///
/// The value format is: `{session_id}.{hmac_hex}` where the HMAC covers
/// the session ID using the provided encryption key. This prevents an
/// attacker from forging or tampering with the session ID.
pub fn create_session_cookie_value(session_id: &str, encryption_key: &[u8]) -> String {
    // HMAC-SHA256 accepts keys of any size, so this never fails.
    let mut mac = HmacSha256::new_from_slice(encryption_key)
        .expect("HMAC-SHA256 accepts keys of any size");
    mac.update(session_id.as_bytes());
    let result = mac.finalize();
    let hmac_hex = hex::encode(result.into_bytes());
    format!("{}.{}", session_id, hmac_hex)
}

/// Verify and extract the session ID from a cookie value.
///
/// Returns `Some(session_id)` if the HMAC is valid, `None` otherwise.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_session_cookie_value(cookie_value: &str, encryption_key: &[u8]) -> Option<String> {
    let parts: Vec<&str> = cookie_value.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }

    let session_id = parts[0];
    let provided_hmac = parts[1];

    // HMAC-SHA256 accepts keys of any size, so this never fails.
    let mut mac = HmacSha256::new_from_slice(encryption_key)
        .expect("HMAC-SHA256 accepts keys of any size");
    mac.update(session_id.as_bytes());
    let expected = mac.finalize();
    let expected_hex = hex::encode(expected.into_bytes());

    // Constant-time comparison to prevent timing attacks
    if expected_hex
        .as_bytes()
        .ct_eq(provided_hmac.as_bytes())
        .into()
    {
        Some(session_id.to_string())
    } else {
        None
    }
}

/// Build the `Set-Cookie` header value for a session cookie.
pub fn session_cookie_header(session_id: &str, encryption_key: &[u8]) -> String {
    let value = create_session_cookie_value(session_id, encryption_key);
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Max-Age={}; Path=/",
        SESSION_COOKIE_NAME, value, SESSION_COOKIE_MAX_AGE
    )
}

/// Build a `Set-Cookie` header that clears (deletes) the session cookie.
pub fn clear_session_cookie_header() -> String {
    format!(
        "{}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/",
        SESSION_COOKIE_NAME
    )
}

/// Extract the session ID from the request's `Cookie` header.
///
/// Parses the `Cookie` header, finds the `oidc_session` cookie, verifies
/// the HMAC, and returns the session ID if valid.
pub fn extract_session_id_from_headers(
    headers: &HeaderMap,
    encryption_key: &[u8],
) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;

    // Parse cookies: "name1=value1; name2=value2; ..."
    for cookie_pair in cookie_header.split(';') {
        let cookie_pair = cookie_pair.trim();
        if let Some(value) = cookie_pair.strip_prefix(&format!("{}=", SESSION_COOKIE_NAME)) {
            if let Some(session_id) = verify_session_cookie_value(value, encryption_key) {
                return Some(session_id);
            }
        }
    }

    None
}

/// Append a `Set-Cookie` header to the response headers.
pub fn append_set_cookie(headers: &mut axum::http::HeaderMap, value: String) {
    if let Ok(header_value) = axum::http::HeaderValue::from_str(&value) {
        headers.append(SET_COOKIE, header_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_create_session_cookie_value_format() {
        let value = create_session_cookie_value("abc123", &test_key());
        // Format: session_id.hmac_hex
        let parts: Vec<&str> = value.splitn(2, '.').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "abc123");
        // HMAC-SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(parts[1].len(), 64);
    }

    #[test]
    fn test_verify_valid_cookie() {
        let value = create_session_cookie_value("session-xyz", &test_key());
        let result = verify_session_cookie_value(&value, &test_key());
        assert_eq!(result, Some("session-xyz".to_string()));
    }

    #[test]
    fn test_verify_rejects_tampered_session_id() {
        let value = create_session_cookie_value("session-xyz", &test_key());
        // Tamper with the session ID part
        let tampered = value.replace("session-xyz", "session-abc");
        let result = verify_session_cookie_value(&tampered, &test_key());
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let value = create_session_cookie_value("session-xyz", &test_key());
        let wrong_key = [0x99u8; 32];
        let result = verify_session_cookie_value(&value, &wrong_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_rejects_malformed_cookie() {
        assert!(verify_session_cookie_value("no-dot-here", &test_key()).is_none());
        assert!(verify_session_cookie_value("", &test_key()).is_none());
        assert!(verify_session_cookie_value(".", &test_key()).is_none());
    }

    #[test]
    fn test_session_cookie_header_contains_flags() {
        let header = session_cookie_header("sid123", &test_key());
        assert!(header.starts_with("oidc_session="));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Max-Age=86400"));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn test_clear_session_cookie_header() {
        let header = clear_session_cookie_header();
        assert!(header.starts_with("oidc_session="));
        assert!(header.contains("Max-Age=0"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn test_extract_session_id_from_headers() {
        let mut headers = HeaderMap::new();
        let value = create_session_cookie_value("my-session", &test_key());
        headers.insert(
            COOKIE,
            axum::http::HeaderValue::from_str(&format!("oidc_session={}", value)).unwrap(),
        );
        let result = extract_session_id_from_headers(&headers, &test_key());
        assert_eq!(result, Some("my-session".to_string()));
    }

    #[test]
    fn test_extract_session_id_missing_cookie() {
        let headers = HeaderMap::new();
        let result = extract_session_id_from_headers(&headers, &test_key());
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_session_id_with_other_cookies() {
        let mut headers = HeaderMap::new();
        let value = create_session_cookie_value("my-session", &test_key());
        headers.insert(
            COOKIE,
            axum::http::HeaderValue::from_str(&format!(
                "other=value; oidc_session={}; lang=en",
                value
            ))
            .unwrap(),
        );
        let result = extract_session_id_from_headers(&headers, &test_key());
        assert_eq!(result, Some("my-session".to_string()));
    }

    #[test]
    fn test_extract_session_id_invalid_hmac() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            axum::http::HeaderValue::from_str("oidc_session=fake-id.badhmac00000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        let result = extract_session_id_from_headers(&headers, &test_key());
        assert!(result.is_none());
    }

    #[test]
    fn test_deterministic_hmac() {
        let v1 = create_session_cookie_value("test-session", &test_key());
        let v2 = create_session_cookie_value("test-session", &test_key());
        assert_eq!(v1, v2, "HMAC should be deterministic for same inputs");
    }

    #[test]
    fn test_different_sessions_different_hmacs() {
        let v1 = create_session_cookie_value("session-a", &test_key());
        let v2 = create_session_cookie_value("session-b", &test_key());
        assert_ne!(v1, v2, "Different session IDs must produce different HMACs");
    }
}
