use oidc_core::errors::OidcError;
use oidc_core::traits::token_service::TokenService;
use oidc_core::traits::Clock;
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
    /// Create a new token service, generating a fresh RSA keypair.
    pub fn new(issuer: impl Into<String>) -> Result<Self, OidcError> {
        let issuer = issuer.into();
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(Self {
            issuer,
            private_key,
            kid: "key-1".to_string(),
            access_token_ttl_secs: 900, // 15 minutes
            id_token_ttl_secs: 3600,    // 1 hour
            clock: Arc::new(oidc_core::traits::clock::SystemClock),
        })
    }

    /// Create a new token service with a custom clock (for testing).
    pub fn with_clock(issuer: impl Into<String>, clock: Arc<dyn Clock>) -> Result<Self, OidcError> {
        let issuer = issuer.into();
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(Self {
            issuer,
            private_key,
            kid: "key-1".to_string(),
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
    fn encode_jwt<Claims: Serialize>(
        &self,
        claims: &Claims,
    ) -> Result<String, OidcError> {
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

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = b64_decode(parts[2]).map_err(|_| OidcError::InvalidTokenSignature)?;

        self.verify_rs256(signing_input.as_bytes(), &signature)
            .map_err(|_| OidcError::InvalidTokenSignature)?;

        let claims_json = b64_decode(parts[1]).map_err(|_| OidcError::InvalidTokenSignature)?;
        let claims: Claims = serde_json::from_slice(&claims_json)
            .map_err(|_| OidcError::InvalidTokenSignature)?;

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

    async fn issue_id_token(
        &self,
        subject: &str,
        audience: &str,
        nonce: Option<&str>,
    ) -> Result<String, OidcError> {
        let now = self.now();
        let claims = IdTokenClaims {
            sub: subject.to_string(),
            aud: audience.to_string(),
            iss: self.issuer.clone(),
            exp: now + self.id_token_ttl_secs,
            iat: now,
            auth_time: now,
            nonce: nonce.map(|s| s.to_string()),
            email: None,
            email_verified: None,
            name: None,
            given_name: None,
            family_name: None,
        };
        self.encode_jwt(&claims)
    }
}

fn b64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

fn b64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let token = service
            .issue_id_token("user-456", "my-client", Some("abc123"))
            .await
            .unwrap();
        assert_eq!(token.split('.').count(), 3);
    }
}
