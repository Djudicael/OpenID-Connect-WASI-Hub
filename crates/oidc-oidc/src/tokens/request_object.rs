//! Request Object verification per OIDC Core §6.
//!
//! A Request Object is a JWT that contains authorization request parameters
//! as claims. It is passed via the `request` parameter (or `request_uri`,
//! which is handled separately via PAR).
//!
//! Reference: <https://openid.net/specs/openid-connect-core-1_0.html#RequestObject>

use std::collections::HashMap;

use oidc_core::errors::OidcError;
use serde::Deserialize;

use super::jwt_service::{JwtHeader, b64_decode, find_jwk_in_jwks, verify_signature_with_jwk};

/// Claims expected inside a Request Object JWT per OIDC Core §6.
///
/// All OIDC authorization request parameters can appear as claims.
/// The `iss` claim MUST equal the `client_id`. The `aud` claim MUST
/// contain the authorization endpoint URL or the issuer identifier.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestObjectClaims {
    /// Issuer — MUST equal the `client_id` of the client.
    pub iss: String,
    /// Audience — MUST contain the authorization endpoint URL or the issuer.
    pub aud: AudValue,
    /// Expiration time (seconds since epoch).
    pub exp: i64,
    /// Issued at (seconds since epoch).
    #[serde(default)]
    pub iat: i64,
    /// Not before (optional, seconds since epoch).
    #[serde(default)]
    pub nbf: Option<i64>,
    /// JWT ID (optional, unique identifier for this request object).
    #[serde(default)]
    pub jti: Option<String>,
    /// The client_id of the client.
    pub client_id: Option<String>,
    /// Response type (e.g. "code", "id_token", etc.).
    #[serde(default)]
    pub response_type: Option<String>,
    /// Redirect URI.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Space-separated scope string.
    #[serde(default)]
    pub scope: Option<String>,
    /// Opaque state value.
    #[serde(default)]
    pub state: Option<String>,
    /// Nonce value.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Display parameter (page, popup, touch, wap).
    #[serde(default)]
    pub display: Option<String>,
    /// Prompt parameter (login, none, consent, select_account).
    #[serde(default)]
    pub prompt: Option<String>,
    /// Maximum authentication age (seconds).
    #[serde(default)]
    pub max_age: Option<i64>,
    /// Hint to the authorization server about the login identifier.
    #[serde(default)]
    pub login_hint: Option<String>,
    /// PKCE code challenge.
    #[serde(default)]
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    /// Claims parameter (JSON value per OIDC Core §5.5).
    #[serde(default)]
    pub claims: Option<serde_json::Value>,
    /// request_uri — MUST be rejected if present per OIDC Core §6.1.
    #[serde(default)]
    pub request_uri: Option<String>,
    /// Response mode (query, fragment, form_post).
    #[serde(default)]
    pub response_mode: Option<String>,
}

/// Audience value — can be a single string or an array of strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum AudValue {
    /// Single audience string.
    Single(String),
    /// Array of audience strings.
    Multiple(Vec<String>),
}

impl AudValue {
    /// Check if the audience contains the expected value.
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            AudValue::Single(s) => s == expected,
            AudValue::Multiple(v) => v.iter().any(|s| s == expected),
        }
    }
}

/// Parse a Request Object JWT without verifying the signature.
/// Returns `(header, claims, signing_input, signature_bytes)`.
fn parse_request_object_unverified(
    token: &str,
) -> Result<(JwtHeader, RequestObjectClaims, String, Vec<u8>), OidcError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(OidcError::InvalidRequestObject("invalid JWT format".into()));
    }
    let header_json = b64_decode(parts[0])
        .map_err(|_| OidcError::InvalidRequestObject("invalid header encoding".into()))?;
    let header: JwtHeader = serde_json::from_slice(&header_json)
        .map_err(|_| OidcError::InvalidRequestObject("invalid header JSON".into()))?;
    let claims_json = b64_decode(parts[1])
        .map_err(|_| OidcError::InvalidRequestObject("invalid claims encoding".into()))?;
    let claims: RequestObjectClaims = serde_json::from_slice(&claims_json)
        .map_err(|e| OidcError::InvalidRequestObject(format!("invalid claims JSON: {e}")))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = b64_decode(parts[2])
        .map_err(|_| OidcError::InvalidRequestObject("invalid signature encoding".into()))?;
    Ok((header, claims, signing_input, signature))
}

/// Verify a Request Object JWT and return its claims as a HashMap.
///
/// This function:
/// 1. Parses the JWT header and claims without verification
/// 2. Validates `iss` == `expected_client_id`
/// 3. Validates `aud` contains `expected_issuer` (the authorization endpoint URL or issuer)
/// 4. Validates `exp` is in the future
/// 5. Validates `iat` is not too far in the future (≤ 5 minutes)
/// 6. If `nbf` is present, validates it's in the past
/// 7. Rejects if `request_uri` claim is present (per OIDC Core §6.1)
/// 8. Verifies the signature against the client's JWKS
/// 9. Returns the verified claims as a HashMap that can be merged with authorize params
pub fn verify_request_object(
    request_jwt: &str,
    client_jwks: &serde_json::Value,
    expected_issuer: &str,
    expected_client_id: &str,
    now: i64,
) -> Result<HashMap<String, String>, OidcError> {
    // 1. Parse without verification
    let (header, claims, signing_input, signature) = parse_request_object_unverified(request_jwt)?;

    // 2. Validate iss == client_id
    if claims.iss != expected_client_id {
        return Err(OidcError::InvalidRequestObject(
            "iss does not match client_id".into(),
        ));
    }

    // 3. Validate aud contains the authorization endpoint URL or the issuer
    if !claims.aud.contains(expected_issuer) {
        return Err(OidcError::InvalidRequestObject(format!(
            "aud does not contain expected issuer '{expected_issuer}'"
        )));
    }

    // 4. Validate exp is in the future
    if claims.exp < now {
        return Err(OidcError::InvalidRequestObject(
            "request object expired".into(),
        ));
    }

    // 5. Validate iat is not too far in the future (≤ 5 minutes)
    if claims.iat > now + 300 {
        return Err(OidcError::InvalidRequestObject(
            "request object issued too far in the future".into(),
        ));
    }

    // 6. If nbf is present, validate it's in the past
    if let Some(nbf) = claims.nbf {
        if nbf > now {
            return Err(OidcError::InvalidRequestObject(
                "request object not yet valid (nbf)".into(),
            ));
        }
    }

    // 7. Reject if request_uri claim is present (per OIDC Core §6.1)
    if claims.request_uri.is_some() {
        return Err(OidcError::InvalidRequestObject(
            "request_uri MUST NOT be included in a Request Object".into(),
        ));
    }

    // 8. Verify the signature against the client's JWKS
    let jwk = find_jwk_in_jwks(client_jwks, &header.kid, &header.alg)?;
    verify_signature_with_jwk(signing_input.as_bytes(), &signature, &jwk)?;

    // 9. Convert claims to HashMap<String, String>
    let mut result = HashMap::new();

    // Always include iss and aud for completeness
    result.insert("iss".to_string(), claims.iss.clone());
    match &claims.aud {
        AudValue::Single(s) => {
            result.insert("aud".to_string(), s.clone());
        }
        AudValue::Multiple(v) => {
            // Serialize array as JSON string
            if let Ok(s) = serde_json::to_string(v) {
                result.insert("aud".to_string(), s);
            }
        }
    }

    // Map optional OIDC authorization request parameters
    if let Some(ref v) = claims.client_id {
        result.insert("client_id".to_string(), v.clone());
    }
    if let Some(ref v) = claims.response_type {
        result.insert("response_type".to_string(), v.clone());
    }
    if let Some(ref v) = claims.redirect_uri {
        result.insert("redirect_uri".to_string(), v.clone());
    }
    if let Some(ref v) = claims.scope {
        result.insert("scope".to_string(), v.clone());
    }
    if let Some(ref v) = claims.state {
        result.insert("state".to_string(), v.clone());
    }
    if let Some(ref v) = claims.nonce {
        result.insert("nonce".to_string(), v.clone());
    }
    if let Some(ref v) = claims.display {
        result.insert("display".to_string(), v.clone());
    }
    if let Some(ref v) = claims.prompt {
        result.insert("prompt".to_string(), v.clone());
    }
    if let Some(v) = claims.max_age {
        result.insert("max_age".to_string(), v.to_string());
    }
    if let Some(ref v) = claims.login_hint {
        result.insert("login_hint".to_string(), v.clone());
    }
    if let Some(ref v) = claims.code_challenge {
        result.insert("code_challenge".to_string(), v.clone());
    }
    if let Some(ref v) = claims.code_challenge_method {
        result.insert("code_challenge_method".to_string(), v.clone());
    }
    if let Some(ref v) = claims.response_mode {
        result.insert("response_mode".to_string(), v.clone());
    }
    if let Some(ref v) = claims.claims {
        if let Ok(s) = serde_json::to_string(v) {
            result.insert("claims".to_string(), s);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    use super::super::jwt_service::b64_encode;

    /// Helper: create an RSA key pair and return (JWKS JSON, RsaPrivateKey, kid).
    fn make_rsa_jwks() -> (serde_json::Value, RsaPrivateKey, String) {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        let kid = "test-rsa-key-1".to_string();
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "alg": "RS256",
                "use": "sig",
                "n": b64_encode(&n),
                "e": b64_encode(&e),
            }]
        });
        (jwks, private_key, kid)
    }

    /// Helper: create an Ed25519 key pair and return (JWKS JSON, SigningKey, kid).
    fn make_eddsa_jwks() -> (serde_json::Value, ed25519_dalek::SigningKey, String) {
        let secret_key: [u8; 32] = rand::random();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        let x = verifying_key.to_bytes();
        let kid = "test-ed-key-1".to_string();
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "kid": kid,
                "alg": "EdDSA",
                "use": "sig",
                "crv": "Ed25519",
                "x": b64_encode(&x),
            }]
        });
        (jwks, signing_key, kid)
    }

    /// Helper: sign a JWT with RS256.
    fn sign_rs256_jwt(header_json: &str, claims_json: &str, private_key: &RsaPrivateKey) -> String {
        let header_b64 = b64_encode(header_json.as_bytes());
        let claims_b64 = b64_encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let signature = signing_key.try_sign(signing_input.as_bytes()).unwrap();
        let signature_b64 = b64_encode(&signature.to_vec());
        format!("{}.{}.{}", header_b64, claims_b64, signature_b64)
    }

    /// Helper: sign a JWT with EdDSA.
    fn sign_eddsa_jwt(
        header_json: &str,
        claims_json: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> String {
        use ed25519_dalek::Signer;
        let header_b64 = b64_encode(header_json.as_bytes());
        let claims_b64 = b64_encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = b64_encode(&signature.to_vec());
        format!("{}.{}.{}", header_b64, claims_b64, signature_b64)
    }

    /// Helper: build a basic claims JSON for a request object.
    fn build_claims_json(
        iss: &str,
        aud: &str,
        exp: i64,
        iat: i64,
        client_id: &str,
        extras: &[(&str, &str)],
    ) -> String {
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String(iss.to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::Value::String(aud.to_string()),
        );
        map.insert("exp".to_string(), serde_json::Number::from(exp).into());
        map.insert("iat".to_string(), serde_json::Number::from(iat).into());
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String(client_id.to_string()),
        );
        for (k, v) in extras {
            // Try to parse as number, otherwise treat as string
            if let Ok(n) = v.parse::<i64>() {
                map.insert(k.to_string(), serde_json::Number::from(n).into());
            } else {
                map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
            }
        }
        serde_json::Value::Object(map).to_string()
    }

    #[test]
    fn test_verify_valid_rs256_request_object() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let claims = build_claims_json(
            "my-client",
            "https://issuer.example.com",
            now + 300,
            now,
            "my-client",
            &[
                ("response_type", "code"),
                ("redirect_uri", "https://example.com/callback"),
                ("scope", "openid profile"),
                ("state", "abc123"),
                ("nonce", "n-123"),
                (
                    "code_challenge",
                    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                ),
                ("code_challenge_method", "S256"),
            ],
        );
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result);
        let params = result.unwrap();
        assert_eq!(params.get("client_id").unwrap(), "my-client");
        assert_eq!(params.get("response_type").unwrap(), "code");
        assert_eq!(params.get("scope").unwrap(), "openid profile");
        assert_eq!(params.get("state").unwrap(), "abc123");
        assert_eq!(params.get("nonce").unwrap(), "n-123");
        assert_eq!(
            params.get("code_challenge").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(params.get("code_challenge_method").unwrap(), "S256");
    }

    #[test]
    fn test_verify_valid_eddsa_request_object() {
        let (jwks, signing_key, kid) = make_eddsa_jwks();
        let now = 1000;
        let claims = build_claims_json(
            "ed-client",
            "https://issuer.example.com",
            now + 300,
            now,
            "ed-client",
            &[
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "ed-state"),
            ],
        );
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_eddsa_jwt(&header, &claims, &signing_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "ed-client", now);
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result);
        let params = result.unwrap();
        assert_eq!(params.get("client_id").unwrap(), "ed-client");
        assert_eq!(params.get("response_type").unwrap(), "code");
    }

    #[test]
    fn test_reject_expired_request_object() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        // exp is in the past
        let claims = build_claims_json(
            "my-client",
            "https://issuer.example.com",
            now - 100,
            now - 400,
            "my-client",
            &[],
        );
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("expired")));
    }

    #[test]
    fn test_reject_wrong_iss() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let claims = build_claims_json(
            "wrong-client",
            "https://issuer.example.com",
            now + 300,
            now,
            "wrong-client",
            &[],
        );
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("iss")));
    }

    #[test]
    fn test_reject_wrong_aud() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let claims = build_claims_json(
            "my-client",
            "https://wrong-aud.example.com",
            now + 300,
            now,
            "my-client",
            &[],
        );
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("aud")));
    }

    #[test]
    fn test_reject_request_uri_in_request_object() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::Value::String("https://issuer.example.com".to_string()),
        );
        map.insert(
            "exp".to_string(),
            serde_json::Number::from(now + 300).into(),
        );
        map.insert("iat".to_string(), serde_json::Number::from(now).into());
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "request_uri".to_string(),
            serde_json::Value::String("urn:ietf:params:oauth:request_uri:abc".to_string()),
        );
        let claims = serde_json::Value::Object(map).to_string();

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("request_uri")));
    }

    #[test]
    fn test_reject_iat_in_future() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        // iat is 6 minutes in the future
        let claims = build_claims_json(
            "my-client",
            "https://issuer.example.com",
            now + 1000,
            now + 400,
            "my-client",
            &[],
        );
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("future")));
    }

    #[test]
    fn test_reject_nbf_in_future() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::Value::String("https://issuer.example.com".to_string()),
        );
        map.insert(
            "exp".to_string(),
            serde_json::Number::from(now + 300).into(),
        );
        map.insert("iat".to_string(), serde_json::Number::from(now).into());
        map.insert(
            "nbf".to_string(),
            serde_json::Number::from(now + 100).into(),
        );
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        let claims = serde_json::Value::Object(map).to_string();

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("nbf")));
    }

    #[test]
    fn test_accept_nbf_in_past() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::Value::String("https://issuer.example.com".to_string()),
        );
        map.insert(
            "exp".to_string(),
            serde_json::Number::from(now + 300).into(),
        );
        map.insert("iat".to_string(), serde_json::Number::from(now).into());
        map.insert(
            "nbf".to_string(),
            serde_json::Number::from(now - 100).into(),
        );
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        let claims = serde_json::Value::Object(map).to_string();

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result);
    }

    #[test]
    fn test_aud_array_contains_issuer() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::json!(["https://other.example.com", "https://issuer.example.com"]),
        );
        map.insert(
            "exp".to_string(),
            serde_json::Number::from(now + 300).into(),
        );
        map.insert("iat".to_string(), serde_json::Number::from(now).into());
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        let claims = serde_json::Value::Object(map).to_string();

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result);
    }

    #[test]
    fn test_aud_array_does_not_contain_issuer() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::json!(["https://other.example.com", "https://another.example.com"]),
        );
        map.insert(
            "exp".to_string(),
            serde_json::Number::from(now + 300).into(),
        );
        map.insert("iat".to_string(), serde_json::Number::from(now).into());
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        let claims = serde_json::Value::Object(map).to_string();

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidRequestObject(ref s) if s.contains("aud")));
    }

    #[test]
    fn test_reject_invalid_jwt_format() {
        let result = verify_request_object(
            "not-a-jwt",
            &serde_json::json!({"keys": []}),
            "https://issuer.example.com",
            "my-client",
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_wrong_signature() {
        let (jwks, _private_key, kid) = make_rsa_jwks();
        // Generate a different key pair
        let (_, other_private_key, _) = make_rsa_jwks();
        let now = 1000;
        let claims = build_claims_json(
            "my-client",
            "https://issuer.example.com",
            now + 300,
            now,
            "my-client",
            &[],
        );
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        // Sign with the wrong key
        let jwt = sign_rs256_jwt(&header, &claims, &other_private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_err());
    }

    #[test]
    fn test_optional_fields_in_result() {
        let (jwks, private_key, kid) = make_rsa_jwks();
        let now = 1000;
        let mut map = serde_json::Map::new();
        map.insert(
            "iss".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "aud".to_string(),
            serde_json::Value::String("https://issuer.example.com".to_string()),
        );
        map.insert(
            "exp".to_string(),
            serde_json::Number::from(now + 300).into(),
        );
        map.insert("iat".to_string(), serde_json::Number::from(now).into());
        map.insert(
            "client_id".to_string(),
            serde_json::Value::String("my-client".to_string()),
        );
        map.insert(
            "response_type".to_string(),
            serde_json::Value::String("code".to_string()),
        );
        map.insert(
            "scope".to_string(),
            serde_json::Value::String("openid".to_string()),
        );
        map.insert(
            "state".to_string(),
            serde_json::Value::String("s123".to_string()),
        );
        map.insert(
            "nonce".to_string(),
            serde_json::Value::String("n456".to_string()),
        );
        map.insert(
            "display".to_string(),
            serde_json::Value::String("page".to_string()),
        );
        map.insert(
            "prompt".to_string(),
            serde_json::Value::String("login".to_string()),
        );
        map.insert("max_age".to_string(), serde_json::Number::from(3600).into());
        map.insert(
            "login_hint".to_string(),
            serde_json::Value::String("user@example.com".to_string()),
        );
        map.insert(
            "response_mode".to_string(),
            serde_json::Value::String("query".to_string()),
        );
        let claims = serde_json::Value::Object(map).to_string();

        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": kid,
        })
        .to_string();
        let jwt = sign_rs256_jwt(&header, &claims, &private_key);

        let result =
            verify_request_object(&jwt, &jwks, "https://issuer.example.com", "my-client", now);
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.get("display").unwrap(), "page");
        assert_eq!(params.get("prompt").unwrap(), "login");
        assert_eq!(params.get("max_age").unwrap(), "3600");
        assert_eq!(params.get("login_hint").unwrap(), "user@example.com");
        assert_eq!(params.get("response_mode").unwrap(), "query");
    }
}
