//! DPoP (Demonstrating Proof of Possession) — RFC 9449.
//!
//! DPoP allows clients to cryptographically bind access tokens to a key pair,
//! preventing token replay by attackers. The client sends a DPoP proof JWT in
//! the `DPoP` HTTP header; the server verifies the proof and binds the issued
//! access token to the client's public key via a `cnf.jkt` claim.

use oidc_core::OidcError;
use serde::Deserialize;

use super::jwt_service::{b64_decode, b64_encode, verify_signature_with_jwk};

// ────────────────────────────────────────────────────────────────────────────
// Structs
// ────────────────────────────────────────────────────────────────────────────

/// DPoP proof JWT header (RFC 9449 §4.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DpopHeader {
    /// MUST be `"dpop+jwt"`.
    pub typ: String,
    /// Signing algorithm: `RS256` or `EdDSA`.
    pub alg: String,
    /// The public key in JWK format, inline in the header (required for DPoP).
    pub jwk: serde_json::Value,
    /// Optional key ID.
    #[serde(default)]
    pub kid: Option<String>,
}

/// DPoP proof JWT claims (RFC 9449 §4.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DpopClaims {
    /// Unique identifier for the proof (prevents replay).
    pub jti: String,
    /// HTTP method (GET, POST, etc.).
    pub htm: String,
    /// HTTP URI (scheme + authority + path, no query/fragment).
    pub htu: String,
    /// Issued-at timestamp (seconds since epoch).
    pub iat: i64,
    /// Base64url SHA-256 hash of the access token (required for protected-resource access).
    #[serde(default)]
    pub ath: Option<String>,
    /// Confirmation claim (optional).
    #[serde(default)]
    pub cnf: Option<serde_json::Value>,
}

/// Result of a successful DPoP proof verification.
#[derive(Debug, Clone)]
pub struct DpopProof {
    /// SHA-256 thumbprint of the JWK (RFC 7638).
    pub jwk_thumbprint: String,
    /// HTTP method from the proof.
    pub htm: String,
    /// HTTP URI from the proof.
    pub htu: String,
    /// Access token hash from the proof (if present).
    pub ath: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Core verification
// ────────────────────────────────────────────────────────────────────────────

/// Allowed time skew for DPoP proof `iat` (5 minutes each side).
const DPOP_TIME_WINDOW_SECS: i64 = 300;

/// Verify a DPoP proof JWT from the `DPoP` HTTP header.
///
/// Per RFC 9449:
/// 1. Parse the JWT (3 parts: header, claims, signature).
/// 2. Validate `typ` == `"dpop+jwt"`.
/// 3. Validate `alg` is `RS256` or `EdDSA`.
/// 4. Validate `jwk` is present in the header and does NOT contain private key material.
/// 5. Validate `jti` is present.
/// 6. Validate `htm` matches the expected HTTP method (case-insensitive).
/// 7. Validate `htu` matches the expected URI (scheme + authority + path).
/// 8. Validate `iat` is within ±5 minutes of `now`.
/// 9. If `access_token` is provided, validate `ath` matches SHA-256(access_token) base64url.
/// 10. Verify the signature using the `jwk` from the header itself.
/// 11. Compute the JWK thumbprint and return it in `DpopProof`.
pub fn verify_dpop_proof(
    dpop_header_value: &str,
    expected_method: &str,
    expected_uri: &str,
    access_token: Option<&str>,
    now: i64,
) -> Result<DpopProof, OidcError> {
    // ── 1. Split JWT ────────────────────────────────────────────────────
    let parts: Vec<&str> = dpop_header_value.split('.').collect();
    if parts.len() != 3 {
        return Err(OidcError::InvalidDPoPProof(
            "DPoP proof must be a JWT with 3 parts".into(),
        ));
    }

    // ── 2. Decode header ─────────────────────────────────────────────────
    let header_bytes = b64_decode(parts[0]).map_err(|_| {
        OidcError::InvalidDPoPProof("DPoP proof header is not valid base64url".into())
    })?;
    let header: DpopHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        OidcError::InvalidDPoPProof(format!("DPoP proof header is not valid JSON: {e}"))
    })?;

    // ── 3. Validate typ ──────────────────────────────────────────────────
    if header.typ != "dpop+jwt" {
        return Err(OidcError::InvalidDPoPProof(format!(
            "DPoP proof typ must be 'dpop+jwt', got '{}'",
            header.typ
        )));
    }

    // ── 4. Validate alg ─────────────────────────────────────────────────
    if header.alg != "RS256" && header.alg != "EdDSA" {
        return Err(OidcError::InvalidDPoPProof(format!(
            "DPoP proof alg must be RS256 or EdDSA, got '{}'",
            header.alg
        )));
    }

    // ── 5. Validate jwk is present and is a public key ───────────────────
    let jwk = &header.jwk;
    if jwk.is_null() || !jwk.is_object() {
        return Err(OidcError::InvalidDPoPProof(
            "DPoP proof header must contain a 'jwk'".into(),
        ));
    }

    // Ensure no private key material is present
    if jwk.get("d").is_some() {
        return Err(OidcError::InvalidDPoPProof(
            "DPoP proof jwk must not contain private key material ('d')".into(),
        ));
    }

    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");

    if kty != "RSA" && kty != "OKP" {
        return Err(OidcError::InvalidDPoPProof(format!(
            "DPoP proof jwk kty must be RSA or OKP, got '{}'",
            kty
        )));
    }

    // ── 6. Decode claims ────────────────────────────────────────────────
    let claims_bytes = b64_decode(parts[1]).map_err(|_| {
        OidcError::InvalidDPoPProof("DPoP proof claims are not valid base64url".into())
    })?;
    let claims: DpopClaims = serde_json::from_slice(&claims_bytes).map_err(|e| {
        OidcError::InvalidDPoPProof(format!("DPoP proof claims are not valid JSON: {e}"))
    })?;

    // ── 7. Validate jti ──────────────────────────────────────────────────
    if claims.jti.is_empty() {
        return Err(OidcError::InvalidDPoPProof(
            "DPoP proof must contain a 'jti' claim".into(),
        ));
    }

    // ── 8. Validate htm ─────────────────────────────────────────────────
    if claims.htm.to_uppercase() != expected_method.to_uppercase() {
        return Err(OidcError::InvalidDPoPProof(format!(
            "DPoP proof htm must be '{}', got '{}'",
            expected_method, claims.htm
        )));
    }

    // ── 9. Validate htu ─────────────────────────────────────────────────
    let normalized_htu = normalize_uri(&claims.htu);
    let normalized_expected = normalize_uri(expected_uri);
    if normalized_htu != normalized_expected {
        return Err(OidcError::InvalidDPoPProof(format!(
            "DPoP proof htu must be '{}', got '{}'",
            normalized_expected, normalized_htu
        )));
    }

    // ── 10. Validate iat ────────────────────────────────────────────────
    let iat_diff = (claims.iat - now).abs();
    if iat_diff > DPOP_TIME_WINDOW_SECS {
        return Err(OidcError::InvalidDPoPProof(format!(
            "DPoP proof iat is outside the acceptable window ({}s from now)",
            iat_diff
        )));
    }

    // ── 11. Validate ath (if access_token provided) ──────────────────────
    if let Some(token) = access_token {
        let expected_ath = compute_ath(token);
        match claims.ath {
            Some(ref ath) if ath == &expected_ath => {}
            Some(_) => {
                return Err(OidcError::InvalidDPoPProof(
                    "DPoP proof ath does not match the access token hash".into(),
                ));
            }
            None => {
                return Err(OidcError::InvalidDPoPProof(
                    "DPoP proof must contain 'ath' when used with a protected resource".into(),
                ));
            }
        }
    }

    // ── 12. Verify signature ────────────────────────────────────────────
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = b64_decode(parts[2]).map_err(|_| {
        OidcError::InvalidDPoPProof("DPoP proof signature is not valid base64url".into())
    })?;

    // The JWK in the DPoP header must have the `alg` field set for
    // `verify_signature_with_jwk` to dispatch correctly.
    let mut jwk_with_alg = jwk.clone();
    if jwk_with_alg.get("alg").is_none() {
        jwk_with_alg
            .as_object_mut()
            .map(|m| m.insert("alg".into(), serde_json::Value::String(header.alg.clone())));
    }

    verify_signature_with_jwk(signing_input.as_bytes(), &signature, &jwk_with_alg).map_err(
        |_| OidcError::InvalidDPoPProof("DPoP proof signature verification failed".into()),
    )?;

    // ── 13. Compute JWK thumbprint ──────────────────────────────────────
    let jwk_thumbprint = compute_jwk_thumbprint(jwk)?;

    Ok(DpopProof {
        jwk_thumbprint,
        htm: claims.htm,
        htu: claims.htu,
        ath: claims.ath,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// JWK thumbprint (RFC 7638)
// ────────────────────────────────────────────────────────────────────────────

/// Compute the JWK thumbprint per RFC 7638.
///
/// For RSA keys: canonical form is `{"e","kty","n"}` sorted, minified JSON,
/// SHA-256, base64url (no padding).
///
/// For OKP (Ed25519) keys: canonical form is `{"crv","kty","x"}` sorted,
/// minified JSON, SHA-256, base64url (no padding).
pub fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, OidcError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::InvalidDPoPProof("JWK missing 'kty'".into()))?;

    let canonical = match kty {
        "RSA" => {
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidDPoPProof("RSA JWK missing 'n'".into()))?;
            let e = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidDPoPProof("RSA JWK missing 'e'".into()))?;
            // RFC 7638 §3.1: members in lexicographic order
            serde_json::json!({
                "e": e,
                "kty": "RSA",
                "n": n,
            })
        }
        "OKP" => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidDPoPProof("OKP JWK missing 'crv'".to_string()))?;
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidDPoPProof("OKP JWK missing 'x'".into()))?;
            // RFC 7638 §3.2: members in lexicographic order
            serde_json::json!({
                "crv": crv,
                "kty": "OKP",
                "x": x,
            })
        }
        _ => {
            return Err(OidcError::InvalidDPoPProof(format!(
                "Unsupported JWK kty for thumbprint: '{}'",
                kty
            )));
        }
    };

    // Minified JSON (no whitespace) — serde_json::to_string produces compact output by default
    let canonical_json = serde_json::to_string(&canonical).map_err(|e| {
        OidcError::InvalidDPoPProof(format!("Failed to serialize canonical JWK: {e}"))
    })?;

    // SHA-256 hash
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let hash = hasher.finalize();

    // Base64url (no padding)
    Ok(b64_encode(&hash))
}

// ────────────────────────────────────────────────────────────────────────────
// Access token hash (ath)
// ────────────────────────────────────────────────────────────────────────────

/// Compute the `ath` value for a DPoP proof.
///
/// Per RFC 9449 §4.3: SHA-256(access_token), base64url-encoded (no padding).
pub fn compute_ath(access_token: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(access_token.as_bytes());
    let hash = hasher.finalize();
    b64_encode(&hash)
}

// ────────────────────────────────────────────────────────────────────────────
// URI normalization
// ────────────────────────────────────────────────────────────────────────────

/// Normalize a URI for DPoP `htu` comparison.
///
/// Per RFC 9449 §4.3: the `htu` claim should match the HTTP URI of the token
/// endpoint, without query strings and fragments (just scheme + authority + path).
fn normalize_uri(uri: &str) -> String {
    // Simple normalization: strip query and fragment
    let without_fragment = uri.split('#').next().unwrap_or(uri);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);

    // Remove trailing slash for consistent comparison
    let trimmed = without_query.trim_end_matches('/');

    // Lowercase the scheme and host (but preserve path case)
    // Handle case-insensitive scheme matching
    let lower = trimmed.to_lowercase();
    if lower.starts_with("https://") {
        // Find the end of the scheme prefix in the original string
        let scheme_end = trimmed
            .char_indices()
            .find(|(_, c)| *c == ':')
            .map(|(i, _)| i + 3) // skip past ://
            .unwrap_or(0);
        let rest = &trimmed[scheme_end..];
        let authority: String = rest
            .chars()
            .take_while(|c| *c != '/')
            .flat_map(|c| c.to_lowercase())
            .collect();
        let path = &rest[authority.len()..];
        format!("https://{}{}", authority, path)
    } else if lower.starts_with("http://") {
        let scheme_end = trimmed
            .char_indices()
            .find(|(_, c)| *c == ':')
            .map(|(i, _)| i + 3) // skip past ://
            .unwrap_or(0);
        let rest = &trimmed[scheme_end..];
        let authority: String = rest
            .chars()
            .take_while(|c| *c != '/')
            .flat_map(|c| c.to_lowercase())
            .collect();
        let path = &rest[authority.len()..];
        format!("http://{}{}", authority, path)
    } else {
        trimmed.to_string()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ath() {
        // SHA-256("test-token") base64url
        let ath = compute_ath("test-token");
        assert!(!ath.is_empty(), "ath should not be empty");
        // Deterministic
        assert_eq!(ath, compute_ath("test-token"));
        // Different token → different hash
        assert_ne!(ath, compute_ath("other-token"));
    }

    #[test]
    fn test_normalize_uri_strips_query_and_fragment() {
        assert_eq!(
            normalize_uri("https://example.com/token?foo=bar#frag"),
            "https://example.com/token"
        );
    }

    #[test]
    fn test_normalize_uri_strips_trailing_slash() {
        assert_eq!(
            normalize_uri("https://example.com/token/"),
            "https://example.com/token"
        );
    }

    #[test]
    fn test_normalize_uri_lowercases_scheme_and_host() {
        assert_eq!(
            normalize_uri("HTTPS://EXAMPLE.COM/Token"),
            "https://example.com/Token"
        );
    }

    #[test]
    fn test_normalize_uri_preserves_path_case() {
        assert_eq!(
            normalize_uri("https://example.com/Token"),
            "https://example.com/Token"
        );
    }

    #[test]
    fn test_compute_jwk_thumbprint_rsa() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXeI2zV4ZI0b6fLBqHx1v4y9sHbdTY9O8T0Gfg6e0AJmIu1W7y1lDj11M9v9M1Y1G5FZ5e9N1w",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "test-key"
        });
        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        // Should be deterministic
        assert_eq!(thumbprint, compute_jwk_thumbprint(&jwk).unwrap());
        // Should be base64url (no padding)
        assert!(
            !thumbprint.contains('='),
            "thumbprint should have no padding"
        );
        assert!(!thumbprint.contains('+'), "thumbprint should be base64url");
    }

    #[test]
    fn test_compute_jwk_thumbprint_okp() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "alg": "EdDSA",
            "kid": "test-ed-key"
        });
        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumbprint, compute_jwk_thumbprint(&jwk).unwrap());
        assert!(
            !thumbprint.contains('='),
            "thumbprint should have no padding"
        );
    }

    #[test]
    fn test_verify_dpop_proof_rejects_wrong_segment_count() {
        let result = verify_dpop_proof("only.two", "POST", "https://example.com/token", None, 1000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidDPoPProof(_)));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_invalid_base64() {
        let result = verify_dpop_proof(
            "!!!.!!!.!!!",
            "POST",
            "https://example.com/token",
            None,
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_dpop_proof_rejects_wrong_typ() {
        // Build a JWT with typ="JWT" instead of "dpop+jwt"
        let header = serde_json::json!({
            "typ": "JWT",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 1000);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("dpop+jwt"));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_unsupported_alg() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "HS256",
            "jwk": {"kty": "oct", "k": "abc"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 1000);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("RS256") || msg.contains("EdDSA"));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_private_key_in_jwk() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB", "d": "secret"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 1000);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("private key"));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_wrong_htm() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "GET",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 1000);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("htm"));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_wrong_htu() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://evil.com/token",
            "iat": 1000
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 1000);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("htu"));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_expired_iat() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000  // way in the past
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 999999);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("iat") || msg.contains("window"));
    }

    #[test]
    fn test_verify_dpop_proof_requires_ath_when_access_token_provided() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000
            // no ath
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(
            &jwt,
            "POST",
            "https://example.com/token",
            Some("some-access-token"),
            1000,
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("ath"));
    }

    #[test]
    fn test_verify_dpop_proof_rejects_wrong_ath() {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": 1000,
            "ath": "wrong-hash-value"
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        let result = verify_dpop_proof(
            &jwt,
            "POST",
            "https://example.com/token",
            Some("some-access-token"),
            1000,
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("ath"));
    }

    #[test]
    fn test_verify_dpop_proof_htm_case_insensitive() {
        // htm in proof is lowercase "post", expected is "POST" — should match
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}
        });
        let claims = serde_json::json!({
            "jti": "test-id",
            "htm": "post",
            "htu": "https://example.com/token",
            "iat": 1000
        });
        let header_b64 = b64_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let claims_b64 = b64_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let jwt = format!("{}.{}.fakesig", header_b64, claims_b64);

        // This should pass htm validation (but fail on signature — that's OK for this test)
        let result = verify_dpop_proof(&jwt, "POST", "https://example.com/token", None, 1000);
        // We expect it to fail on signature, not on htm
        if let Err(e) = &result {
            let msg = format!("{}", e);
            assert!(
                !msg.contains("htm"),
                "htm should have matched case-insensitively, but got: {}",
                msg
            );
        }
    }
}
