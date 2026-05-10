use oidc_core::errors::OidcError;
use oidc_core::traits::Clock;
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

/// JWT header.
#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// JWT claims for an access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
}

/// JWT claims for an ID token.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

/// A JWK (JSON Web Key) entry for JWKS endpoint.
#[derive(Debug, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub n: String,
    pub e: String,
}

/// JWKS document.
#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Pure-Rust JWT token service using RS256 (WASM-compatible).
pub struct JwtTokenService {
    issuer: String,
    private_key: RsaPrivateKey,
    kid: String,
    access_token_ttl_secs: i64,
    id_token_ttl_secs: i64,
    clock: Arc<dyn Clock>,
}

impl Clone for JwtTokenService {
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            private_key: self.private_key.clone(),
            kid: self.kid.clone(),
            access_token_ttl_secs: self.access_token_ttl_secs,
            id_token_ttl_secs: self.id_token_ttl_secs,
            clock: Arc::new(oidc_core::traits::clock::SystemClock),
        }
    }
}

impl JwtTokenService {
    /// Create a new token service.
    /// Attempts to load the RSA private key from `OIDC_SIGNING_KEY` env var (PEM format).
    /// Falls back to generating a fresh keypair if the env var is not set.
    pub fn new(issuer: impl Into<String>) -> Result<Self, OidcError> {
        let issuer = issuer.into();
        let (private_key, kid) = match std::env::var("OIDC_SIGNING_KEY") {
            Ok(pem) => {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                let key = RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|e| {
                    OidcError::Internal(format!("invalid OIDC_SIGNING_KEY PEM: {e}"))
                })?;
                let kid = std::env::var("OIDC_SIGNING_KID").unwrap_or_else(|_| "key-1".to_string());
                (key, kid)
            }
            Err(_) => {
                use rand::rngs::OsRng;
                let mut rng = OsRng;
                let key = RsaPrivateKey::new(&mut rng, 2048)
                    .map_err(|e| OidcError::Internal(e.to_string()))?;
                (key, "key-1".to_string())
            }
        };

        Ok(Self {
            issuer,
            private_key,
            kid,
            access_token_ttl_secs: 900,
            id_token_ttl_secs: 3600,
            clock: Arc::new(oidc_core::traits::clock::SystemClock),
        })
    }

    /// Create a new token service with a custom clock (for testing).
    pub fn with_clock(issuer: impl Into<String>, clock: Arc<dyn Clock>) -> Result<Self, OidcError> {
        let issuer = issuer.into();
        let (private_key, kid) = match std::env::var("OIDC_SIGNING_KEY") {
            Ok(pem) => {
                use rsa::pkcs1::DecodeRsaPrivateKey;
                let key = RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|e| {
                    OidcError::Internal(format!("invalid OIDC_SIGNING_KEY PEM: {e}"))
                })?;
                let kid = std::env::var("OIDC_SIGNING_KID").unwrap_or_else(|_| "key-1".to_string());
                (key, kid)
            }
            Err(_) => {
                use rand::rngs::OsRng;
                let mut rng = OsRng;
                let key = RsaPrivateKey::new(&mut rng, 2048)
                    .map_err(|e| OidcError::Internal(e.to_string()))?;
                (key, "key-1".to_string())
            }
        };

        Ok(Self {
            issuer,
            private_key,
            kid,
            access_token_ttl_secs: 900,
            id_token_ttl_secs: 3600,
            clock,
        })
    }

    /// Build a JWKS document from the public key.
    pub fn jwks(&self) -> Result<Jwks, OidcError> {
        let public_key = RsaPublicKey::from(&self.private_key);

        let n = b64_encode(&public_key.n().to_bytes_be());
        let e = b64_encode(&public_key.e().to_bytes_be());

        Ok(Jwks {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: self.kid.clone(),
                alg: "RS256".to_string(),
                key_use: "sig".to_string(),
                n,
                e,
            }],
        })
    }

    fn now(&self) -> i64 {
        self.clock.now_secs()
    }

    /// Encode a JWT manually: base64url(header) + "." + base64url(payload) + "." + base64url(signature)
    fn encode_jwt<Claims: Serialize>(&self, claims: &Claims) -> Result<String, OidcError> {
        let header = JwtHeader {
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
            kid: self.kid.clone(),
        };

        let header_json = serde_json::to_string(&header)
            .map_err(|e| OidcError::Internal(format!("jwt header serialize: {e}")))?;
        let claims_json = serde_json::to_string(claims)
            .map_err(|e| OidcError::Internal(format!("jwt claims serialize: {e}")))?;

        let header_b64 = b64_encode(header_json.as_bytes());
        let claims_b64 = b64_encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        let signature = self.sign_rs256(signing_input.as_bytes())?;
        let signature_b64 = b64_encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Sign data with RSASSA-PKCS1-v1_5-SHA256.
    fn sign_rs256(&self, data: &[u8]) -> Result<Vec<u8>, OidcError> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};

        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature = signing_key
            .try_sign(data)
            .map_err(|e| OidcError::Internal(format!("rsa sign failed: {e}")))?;

        Ok(signature.to_vec())
    }

    /// Verify a JWT and return the payload.
    fn decode_jwt<Claims: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<Claims, OidcError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(OidcError::InvalidTokenSignature);
        }

        // Validate the algorithm header to prevent alg:none and key-confusion attacks
        let header_json = b64_decode(parts[0]).map_err(|_| OidcError::InvalidTokenSignature)?;
        let header: JwtHeader =
            serde_json::from_slice(&header_json).map_err(|_| OidcError::InvalidTokenSignature)?;
        if header.alg != "RS256" {
            return Err(OidcError::InvalidTokenSignature);
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = b64_decode(parts[2]).map_err(|_| OidcError::InvalidTokenSignature)?;

        self.verify_rs256(signing_input.as_bytes(), &signature)
            .map_err(|_| OidcError::InvalidTokenSignature)?;

        let claims_json = b64_decode(parts[1]).map_err(|_| OidcError::InvalidTokenSignature)?;
        let claims: Claims =
            serde_json::from_slice(&claims_json).map_err(|_| OidcError::InvalidTokenSignature)?;

        Ok(claims)
    }

    /// Verify RSASSA-PKCS1-v1_5-SHA256 signature.
    fn verify_rs256(&self, data: &[u8], signature: &[u8]) -> Result<(), OidcError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from(&self.private_key);
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let sig = Signature::try_from(signature)
            .map_err(|e| OidcError::Internal(format!("invalid signature length: {e}")))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| OidcError::InvalidTokenSignature)
    }
}

#[async_trait::async_trait]
impl TokenService for JwtTokenService {
    async fn issue_access_token(
        &self,
        subject: &str,
        audience: &str,
        scopes: &[String],
    ) -> Result<String, OidcError> {
        let now = self.now();
        let claims = AccessTokenClaims {
            sub: subject.to_string(),
            aud: audience.to_string(),
            iss: self.issuer.clone(),
            exp: now + self.access_token_ttl_secs,
            iat: now,
            scope: scopes.join(" "),
        };
        self.encode_jwt(&claims)
    }

    async fn verify_access_token(&self, token: &str) -> Result<String, OidcError> {
        let claims: AccessTokenClaims = self.decode_jwt(token)?;
        let now = self.now();
        if claims.exp < now {
            return Err(OidcError::TokenExpired);
        }
        if claims.iss != self.issuer {
            return Err(OidcError::InvalidTokenSignature);
        }
        Ok(claims.sub)
    }

    async fn verify_access_token_with_claims(
        &self,
        token: &str,
    ) -> Result<oidc_core::traits::token_service::VerifiedAccessToken, OidcError> {
        let claims: AccessTokenClaims = self.decode_jwt(token)?;
        let now = self.now();
        if claims.exp < now {
            return Err(OidcError::TokenExpired);
        }
        if claims.iss != self.issuer {
            return Err(OidcError::InvalidTokenSignature);
        }
        Ok(oidc_core::traits::token_service::VerifiedAccessToken {
            sub: claims.sub,
            aud: claims.aud,
            iss: claims.iss,
            exp: claims.exp,
            iat: claims.iat,
            scope: claims.scope,
        })
    }

    async fn verify_id_token(&self, token: &str) -> Result<String, OidcError> {
        let claims: IdTokenClaims = self.decode_jwt(token)?;
        let now = self.now();
        if claims.exp < now {
            return Err(OidcError::TokenExpired);
        }
        if claims.iss != self.issuer {
            return Err(OidcError::InvalidTokenSignature);
        }
        Ok(claims.sub)
    }

    async fn issue_id_token(
        &self,
        subject: &str,
        audience: &str,
        extra: Option<IdTokenExtraClaims>,
    ) -> Result<String, OidcError> {
        let now = self.now();
        let extra = extra.unwrap_or_default();
        let claims = IdTokenClaims {
            sub: subject.to_string(),
            aud: audience.to_string(),
            iss: self.issuer.clone(),
            exp: now + self.id_token_ttl_secs,
            iat: now,
            auth_time: extra.auth_time.unwrap_or(now),
            nonce: extra.nonce,
            at_hash: extra.at_hash,
            c_hash: extra.c_hash,
            email: extra.email,
            email_verified: extra.email_verified,
            name: extra.name,
            given_name: extra.given_name,
            family_name: extra.family_name,
        };
        self.encode_jwt(&claims)
    }
}

fn b64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

fn b64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[tokio::test]
    async fn test_jwt_roundtrip() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let token = service
            .issue_access_token("user-123", "my-client", &["openid".to_string()])
            .await
            .unwrap();
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3);

        let subject = service.verify_access_token(&token).await.unwrap();
        assert_eq!(subject, "user-123");
    }

    #[tokio::test]
    async fn test_jwks_output() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let jwks = service.jwks().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].alg, "RS256");
    }

    #[tokio::test]
    async fn test_id_token() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let extra = IdTokenExtraClaims {
            nonce: Some("abc123".to_string()),
            ..Default::default()
        };
        let token = service
            .issue_id_token("user-456", "my-client", Some(extra))
            .await
            .unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_jwt_rejects_alg_none() {
        // Craft a token with alg: "none" — should be rejected
        let header = serde_json::json!({"alg": "none", "typ": "JWT", "kid": "key-1"});
        let claims = serde_json::json!({"sub": "user-123", "aud": "my-client", "iss": "https://test.example.com", "exp": 9999999999i64, "iat": 1000000, "scope": "openid"});
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let fake_token = format!("{}.{}.", header_b64, claims_b64); // empty signature

        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err(), "Should reject alg:none token");
    }

    #[tokio::test]
    async fn test_id_token_with_hashes() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let extra = IdTokenExtraClaims {
            at_hash: Some("at_hash_value".to_string()),
            c_hash: Some("c_hash_value".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            ..Default::default()
        };
        let token = service
            .issue_id_token("user-456", "my-client", Some(extra))
            .await
            .unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    // ---- Malformed JWT tests ----

    #[tokio::test]
    async fn test_jwt_rejects_corrupted_base64_header() {
        // Header with invalid base64url characters
        let fake_token = "!!!invalid!!!.eyJzdWIiOiJ1c2VyLTEyMyJ9.c2lnbmF0dXJl";
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(fake_token).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwt_rejects_corrupted_base64_claims() {
        // Valid header base64 but corrupted claims
        let header_b64 = b64_encode(r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#.as_bytes());
        let fake_token = format!("{}.!!!invalid!!!.c2lnbmF0dXJl", header_b64);
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwt_rejects_corrupted_base64_signature() {
        // Valid header and claims base64 but corrupted signature
        let header_b64 = b64_encode(r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#.as_bytes());
        let claims_b64 = b64_encode(r#"{"sub":"user-123","aud":"my-client","iss":"https://test.example.com","exp":9999999999,"iat":1000000,"scope":"openid"}"#.as_bytes());
        let fake_token = format!("{}.{}.!!!invalid!!!", header_b64, claims_b64);
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwt_rejects_empty_signature() {
        // Token with empty signature segment
        let header_b64 = b64_encode(r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#.as_bytes());
        let claims_b64 = b64_encode(r#"{"sub":"user-123","aud":"my-client","iss":"https://test.example.com","exp":9999999999,"iat":1000000,"scope":"openid"}"#.as_bytes());
        let fake_token = format!("{}.{}.{}", header_b64, claims_b64, "");
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwt_rejects_wrong_number_of_segments() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        // Only two segments
        let result = service.verify_access_token("a.b").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));

        // Four segments
        let result = service.verify_access_token("a.b.c.d").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwt_rejects_non_utf8_header() {
        // Valid base64 but decoded bytes are not valid JSON/UTF-8
        // 0xFF 0xFE is not valid UTF-8
        let non_utf8_bytes = vec![0xFF, 0xFE, 0xFD];
        let header_b64 = b64_encode(&non_utf8_bytes);
        let claims_b64 = b64_encode(r#"{"sub":"user-123"}"#.as_bytes());
        let fake_token = format!("{}.{}.c2lnbmF0dXJl", header_b64, claims_b64);
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwt_rejects_wrong_kid() {
        // Valid structure but kid doesn't match
        let header_b64 = b64_encode(r#"{"alg":"RS256","typ":"JWT","kid":"wrong-key"}"#.as_bytes());
        let claims_b64 = b64_encode(r#"{"sub":"user-123","aud":"my-client","iss":"https://test.example.com","exp":9999999999,"iat":1000000,"scope":"openid"}"#.as_bytes());
        let fake_token = format!("{}.{}.c2lnbmF0dXJl", header_b64, claims_b64);
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err());
        // Wrong kid still results in signature failure since the key won't match
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }
}
