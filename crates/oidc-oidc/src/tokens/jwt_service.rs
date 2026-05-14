use ed25519_dalek::SigningKey;
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

/// A JWK (JSON Web Key) entry for JWKS endpoint — supports RSA and OKP (Ed25519).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Jwk {
    /// RSA public key.
    Rsa {
        kty: String,
        kid: String,
        alg: String,
        #[serde(rename = "use")]
        key_use: String,
        n: String,
        e: String,
    },
    /// OKP (Octet Key Pair) public key — Ed25519.
    Okp {
        kty: String,
        kid: String,
        alg: String,
        #[serde(rename = "use")]
        key_use: String,
        crv: String,
        x: String,
    },
}

/// JWKS document.
#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Pure-Rust JWT token service using RS256 and EdDSA (WASM-compatible).
pub struct JwtTokenService {
    issuer: String,
    rsa_private_key: RsaPrivateKey,
    rsa_kid: String,
    ed_signing_key: SigningKey,
    ed_kid: String,
    access_token_ttl_secs: i64,
    id_token_ttl_secs: i64,
    clock: Arc<dyn Clock>,
}

impl Clone for JwtTokenService {
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            rsa_private_key: self.rsa_private_key.clone(),
            rsa_kid: self.rsa_kid.clone(),
            ed_signing_key: self.ed_signing_key.clone(),
            ed_kid: self.ed_kid.clone(),
            access_token_ttl_secs: self.access_token_ttl_secs,
            id_token_ttl_secs: self.id_token_ttl_secs,
            clock: Arc::new(oidc_core::traits::clock::SystemClock),
        }
    }
}

impl JwtTokenService {
    /// Create a new token service.
    ///
    /// **Production requirement:** Every WASM instance must load the same signing
    /// keys, otherwise tokens issued by instance *N* will fail verification on
    /// instance *N+1*. In `wasmtime serve` each request may spin up a fresh
    /// component (depending on `--max-instance-reuse-count`), so ephemeral
    /// random keys break SSO across requests.
    ///
    /// Set these environment variables before starting the server:
    ///
    /// ```bash
    /// # Generate once, reuse everywhere
    /// openssl genrsa -out rsa.pem 2048
    /// openssl genpkey -algorithm Ed25519 -out ed25519.pem
    ///
    /// export OIDC_SIGNING_KEY="$(cat rsa.pem)"
    /// export OIDC_SIGNING_KID="key-1"
    /// export OIDC_ED25519_KEY="$(cat ed25519.pem)"
    /// export OIDC_ED25519_KID="ed-key-1"
    /// ```
    ///
    /// If the variables are absent, fresh random keys are generated (fine for
    /// single-instance dev, fatal for multi-request production).
    pub fn new(issuer: impl Into<String>) -> Result<Self, OidcError> {
        let issuer = issuer.into();
        let (rsa_private_key, rsa_kid) = load_rsa_key()?;
        let (ed_signing_key, ed_kid) = load_ed25519_key()?;

        Ok(Self {
            issuer,
            rsa_private_key,
            rsa_kid,
            ed_signing_key,
            ed_kid,
            access_token_ttl_secs: 900,
            id_token_ttl_secs: 3600,
            clock: Arc::new(oidc_core::traits::clock::SystemClock),
        })
    }

    /// Create a new token service with a custom clock (for testing).
    pub fn with_clock(issuer: impl Into<String>, clock: Arc<dyn Clock>) -> Result<Self, OidcError> {
        let issuer = issuer.into();
        let (rsa_private_key, rsa_kid) = load_rsa_key()?;
        let (ed_signing_key, ed_kid) = load_ed25519_key()?;

        Ok(Self {
            issuer,
            rsa_private_key,
            rsa_kid,
            ed_signing_key,
            ed_kid,
            access_token_ttl_secs: 900,
            id_token_ttl_secs: 3600,
            clock,
        })
    }

    /// Create a token service from explicit PEM keys (for a specific realm).
    pub fn from_pems(
        issuer: impl Into<String>,
        rsa_private_pem: &str,
        rsa_kid: &str,
        ed25519_private_pem: &str,
        ed25519_kid: &str,
    ) -> Result<Self, OidcError> {
        let issuer = issuer.into();

        use rsa::pkcs1::DecodeRsaPrivateKey;
        let rsa_private_key = RsaPrivateKey::from_pkcs1_pem(rsa_private_pem)
            .map_err(|e| OidcError::Internal(format!("invalid RSA PEM: {e}")))?;

        use pkcs8::DecodePrivateKey;
        let ed_signing_key = SigningKey::from_pkcs8_pem(ed25519_private_pem)
            .map_err(|e| OidcError::Internal(format!("invalid Ed25519 PEM: {e}")))?;

        Ok(Self {
            issuer,
            rsa_private_key,
            rsa_kid: rsa_kid.to_string(),
            ed_signing_key,
            ed_kid: ed25519_kid.to_string(),
            access_token_ttl_secs: 900,
            id_token_ttl_secs: 3600,
            clock: Arc::new(oidc_core::traits::clock::SystemClock),
        })
    }

    /// Build a JWKS from public key components (no private key needed).
    /// Used by the per-realm certs endpoint.
    pub fn jwks_from_public_keys(
        rsa_kid: &str,
        rsa_n_b64: &str,
        rsa_e_b64: &str,
        ed_kid: &str,
        ed_x_b64: &str,
    ) -> Jwks {
        let rsa_jwk = Jwk::Rsa {
            kty: "RSA".to_string(),
            kid: rsa_kid.to_string(),
            alg: "RS256".to_string(),
            key_use: "sig".to_string(),
            n: rsa_n_b64.to_string(),
            e: rsa_e_b64.to_string(),
        };

        let ed_jwk = Jwk::Okp {
            kty: "OKP".to_string(),
            kid: ed_kid.to_string(),
            alg: "EdDSA".to_string(),
            key_use: "sig".to_string(),
            crv: "Ed25519".to_string(),
            x: ed_x_b64.to_string(),
        };

        Jwks {
            keys: vec![rsa_jwk, ed_jwk],
        }
    }

    /// Build a JWKS document from the public keys (RSA + Ed25519).
    pub fn jwks(&self) -> Result<Jwks, OidcError> {
        let public_key = RsaPublicKey::from(&self.rsa_private_key);

        let n = b64_encode(&public_key.n().to_bytes_be());
        let e = b64_encode(&public_key.e().to_bytes_be());

        let rsa_jwk = Jwk::Rsa {
            kty: "RSA".to_string(),
            kid: self.rsa_kid.clone(),
            alg: "RS256".to_string(),
            key_use: "sig".to_string(),
            n,
            e,
        };

        let verifying_key = self.ed_signing_key.verifying_key();
        let x = b64_encode(&verifying_key.to_bytes());

        let ed_jwk = Jwk::Okp {
            kty: "OKP".to_string(),
            kid: self.ed_kid.clone(),
            alg: "EdDSA".to_string(),
            key_use: "sig".to_string(),
            crv: "Ed25519".to_string(),
            x,
        };

        Ok(Jwks {
            keys: vec![rsa_jwk, ed_jwk],
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
            kid: self.rsa_kid.clone(),
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

    /// Encode a JWT with EdDSA signing.
    fn encode_jwt_eddsa<Claims: Serialize>(&self, claims: &Claims) -> Result<String, OidcError> {
        let header = JwtHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
            kid: self.ed_kid.clone(),
        };

        let header_json = serde_json::to_string(&header)
            .map_err(|e| OidcError::Internal(format!("jwt header serialize: {e}")))?;
        let claims_json = serde_json::to_string(claims)
            .map_err(|e| OidcError::Internal(format!("jwt claims serialize: {e}")))?;

        let header_b64 = b64_encode(header_json.as_bytes());
        let claims_b64 = b64_encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        let signature = self.sign_eddsa_raw(signing_input.as_bytes())?;
        let signature_b64 = b64_encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Sign data with RSASSA-PKCS1-v1_5-SHA256.
    fn sign_rs256(&self, data: &[u8]) -> Result<Vec<u8>, OidcError> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};

        let signing_key = SigningKey::<Sha256>::new(self.rsa_private_key.clone());
        let signature = signing_key
            .try_sign(data)
            .map_err(|e| OidcError::Internal(format!("rsa sign failed: {e}")))?;

        Ok(signature.to_vec())
    }

    /// Sign data with Ed25519 (EdDSA) — raw bytes in, raw 64-byte signature out.
    fn sign_eddsa_raw(&self, data: &[u8]) -> Result<Vec<u8>, OidcError> {
        use ed25519_dalek::Signer;
        let signature = self.ed_signing_key.sign(data);
        Ok(signature.to_vec())
    }

    /// Verify a JWT and return the payload.
    /// Dispatches to RS256 or EdDSA verification based on the `alg` header.
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

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = b64_decode(parts[2]).map_err(|_| OidcError::InvalidTokenSignature)?;

        match header.alg.as_str() {
            "RS256" => {
                self.verify_rs256(signing_input.as_bytes(), &signature)
                    .map_err(|_| OidcError::InvalidTokenSignature)?;
            }
            "EdDSA" => {
                self.verify_eddsa(signing_input.as_bytes(), &signature)
                    .map_err(|_| OidcError::InvalidTokenSignature)?;
            }
            _ => {
                return Err(OidcError::InvalidTokenSignature);
            }
        }

        let claims_json = b64_decode(parts[1]).map_err(|_| OidcError::InvalidTokenSignature)?;
        let claims: Claims =
            serde_json::from_slice(&claims_json).map_err(|_| OidcError::InvalidTokenSignature)?;

        Ok(claims)
    }

    /// Verify RSASSA-PKCS1-v1_5-SHA256 signature.
    fn verify_rs256(&self, data: &[u8], signature: &[u8]) -> Result<(), OidcError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from(&self.rsa_private_key);
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let sig = Signature::try_from(signature)
            .map_err(|e| OidcError::Internal(format!("invalid signature length: {e}")))?;

        verifying_key
            .verify(data, &sig)
            .map_err(|_| OidcError::InvalidTokenSignature)
    }

    /// Verify Ed25519 (EdDSA) signature.
    fn verify_eddsa(&self, data: &[u8], signature: &[u8]) -> Result<(), OidcError> {
        use ed25519_dalek::{Signature, Verifier};

        let sig = Signature::try_from(signature)
            .map_err(|e| OidcError::Internal(format!("invalid eddsa signature: {e}")))?;

        let verifying_key = self.ed_signing_key.verifying_key();
        verifying_key
            .verify(data, &sig)
            .map_err(|_| OidcError::InvalidTokenSignature)
    }

    /// Sign claims with EdDSA and return the JWT string.
    pub fn sign_eddsa<Claims: Serialize>(&self, claims: &Claims) -> Result<String, OidcError> {
        self.encode_jwt_eddsa(claims)
    }

    /// Verify an EdDSA-signed JWT token and return the claims.
    pub fn verify_eddsa_token<Claims: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<Claims, OidcError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(OidcError::InvalidTokenSignature);
        }

        let header_json = b64_decode(parts[0]).map_err(|_| OidcError::InvalidTokenSignature)?;
        let header: JwtHeader =
            serde_json::from_slice(&header_json).map_err(|_| OidcError::InvalidTokenSignature)?;

        if header.alg != "EdDSA" {
            return Err(OidcError::InvalidTokenSignature);
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = b64_decode(parts[2]).map_err(|_| OidcError::InvalidTokenSignature)?;

        self.verify_eddsa(signing_input.as_bytes(), &signature)
            .map_err(|_| OidcError::InvalidTokenSignature)?;

        let claims_json = b64_decode(parts[1]).map_err(|_| OidcError::InvalidTokenSignature)?;
        let claims: Claims =
            serde_json::from_slice(&claims_json).map_err(|_| OidcError::InvalidTokenSignature)?;

        Ok(claims)
    }
}

/// Load the RSA private key from `OIDC_SIGNING_KEY` env var, or generate a fresh one.
fn load_rsa_key() -> Result<(RsaPrivateKey, String), OidcError> {
    match std::env::var("OIDC_SIGNING_KEY") {
        Ok(pem) => {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            let key = RsaPrivateKey::from_pkcs1_pem(&pem)
                .map_err(|e| OidcError::Internal(format!("invalid OIDC_SIGNING_KEY PEM: {e}")))?;
            let kid = std::env::var("OIDC_SIGNING_KID").unwrap_or_else(|_| "key-1".to_string());
            Ok((key, kid))
        }
        Err(_) => {
            use rand::rngs::OsRng;
            let mut rng = OsRng;
            let key = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|e| OidcError::Internal(e.to_string()))?;
            Ok((key, "key-1".to_string()))
        }
    }
}

/// Load the Ed25519 private key from `OIDC_ED25519_KEY` env var (PKCS8 PEM), or generate a fresh one.
fn load_ed25519_key() -> Result<(SigningKey, String), OidcError> {
    match std::env::var("OIDC_ED25519_KEY") {
        Ok(pem) => {
            use pkcs8::DecodePrivateKey;
            let signing_key = SigningKey::from_pkcs8_pem(&pem)
                .map_err(|e| OidcError::Internal(format!("invalid OIDC_ED25519_KEY PEM: {e}")))?;
            let kid = std::env::var("OIDC_ED25519_KID").unwrap_or_else(|_| "ed-key-1".to_string());
            Ok((signing_key, kid))
        }
        Err(_) => {
            let secret_key: [u8; 32] = rand::random();
            let signing_key = SigningKey::from_bytes(&secret_key);
            Ok((signing_key, "ed-key-1".to_string()))
        }
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
        assert_eq!(jwks.keys.len(), 2);

        // RSA key
        assert!(matches!(&jwks.keys[0], Jwk::Rsa { .. }));
        if let Jwk::Rsa { kty, alg, .. } = &jwks.keys[0] {
            assert_eq!(kty, "RSA");
            assert_eq!(alg, "RS256");
        }

        // Ed25519 key
        assert!(matches!(&jwks.keys[1], Jwk::Okp { .. }));
        if let Jwk::Okp { kty, alg, crv, .. } = &jwks.keys[1] {
            assert_eq!(kty, "OKP");
            assert_eq!(alg, "EdDSA");
            assert_eq!(crv, "Ed25519");
        }
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
    async fn test_jwt_rejects_alg_hs256() {
        // Craft a token with alg: "HS256" — should be rejected
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "key-1"});
        let claims = serde_json::json!({"sub": "user-123", "aud": "my-client", "iss": "https://test.example.com", "exp": 9999999999i64, "iat": 1000000, "scope": "openid"});
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let fake_token = format!("{}.{}.fakesignature", header_b64, claims_b64);

        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err(), "Should reject alg:HS256 token");
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
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

    // ---- EdDSA tests ----

    #[tokio::test]
    async fn test_eddsa_roundtrip() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let now = service.now();
        let claims = AccessTokenClaims {
            sub: "user-ed-123".to_string(),
            aud: "my-client".to_string(),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
        };

        let token = service.sign_eddsa(&claims).unwrap();
        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3);

        // Verify via decode_jwt (which dispatches on alg header)
        let decoded: AccessTokenClaims = service.decode_jwt(&token).unwrap();
        assert_eq!(decoded.sub, "user-ed-123");

        // Verify via verify_eddsa_token
        let decoded2: AccessTokenClaims = service.verify_eddsa_token(&token).unwrap();
        assert_eq!(decoded2.sub, "user-ed-123");
    }

    #[tokio::test]
    async fn test_eddsa_verify_via_verify_access_token() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let now = service.now();
        let claims = AccessTokenClaims {
            sub: "user-ed-456".to_string(),
            aud: "my-client".to_string(),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
        };

        let token = service.sign_eddsa(&claims).unwrap();

        // verify_access_token uses decode_jwt internally, which dispatches on alg
        let subject = service.verify_access_token(&token).await.unwrap();
        assert_eq!(subject, "user-ed-456");
    }

    #[tokio::test]
    async fn test_rs256_tokens_still_verified() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        // issue_access_token uses RS256 by default
        let token = service
            .issue_access_token("user-rs256", "my-client", &["openid".to_string()])
            .await
            .unwrap();

        let subject = service.verify_access_token(&token).await.unwrap();
        assert_eq!(subject, "user-rs256");
    }

    #[tokio::test]
    async fn test_eddsa_rejects_alg_none() {
        let header = serde_json::json!({"alg": "none", "typ": "JWT", "kid": "ed-key-1"});
        let claims = serde_json::json!({"sub": "user-123", "aud": "my-client", "iss": "https://test.example.com", "exp": 9999999999i64, "iat": 1000000, "scope": "openid"});
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let fake_token = format!("{}.{}.", header_b64, claims_b64);

        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err(), "Should reject alg:none token");
    }

    #[tokio::test]
    async fn test_eddsa_rejects_hs256() {
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "ed-key-1"});
        let claims = serde_json::json!({"sub": "user-123", "aud": "my-client", "iss": "https://test.example.com", "exp": 9999999999i64, "iat": 1000000, "scope": "openid"});
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let fake_token = format!("{}.{}.fakesignature", header_b64, claims_b64);

        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let result = service.verify_access_token(&fake_token).await;
        assert!(result.is_err(), "Should reject alg:HS256 token");
        assert!(matches!(
            result.unwrap_err(),
            OidcError::InvalidTokenSignature
        ));
    }

    #[tokio::test]
    async fn test_jwks_includes_both_keys() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let jwks = service.jwks().unwrap();
        assert_eq!(jwks.keys.len(), 2);

        let has_rsa = jwks.keys.iter().any(|k| matches!(k, Jwk::Rsa { .. }));
        let has_okp = jwks.keys.iter().any(|k| matches!(k, Jwk::Okp { .. }));
        assert!(has_rsa, "JWKS should contain an RSA key");
        assert!(has_okp, "JWKS should contain an OKP (Ed25519) key");
    }

    #[tokio::test]
    async fn test_eddsa_id_token_roundtrip() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let now = service.now();
        let claims = IdTokenClaims {
            sub: "user-ed-id".to_string(),
            aud: "my-client".to_string(),
            iss: "https://test.example.com".to_string(),
            exp: now + 3600,
            iat: now,
            auth_time: now,
            nonce: Some("nonce-abc".to_string()),
            at_hash: None,
            c_hash: None,
            email: Some("ed@example.com".to_string()),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
        };

        let token = service.sign_eddsa(&claims).unwrap();
        let decoded: IdTokenClaims = service.decode_jwt(&token).unwrap();
        assert_eq!(decoded.sub, "user-ed-id");
        assert_eq!(decoded.nonce, Some("nonce-abc".to_string()));
        assert_eq!(decoded.email, Some("ed@example.com".to_string()));
    }

    #[tokio::test]
    async fn test_eddsa_rejects_wrong_signature() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let now = service.now();
        let claims = AccessTokenClaims {
            sub: "user-ed-789".to_string(),
            aud: "my-client".to_string(),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
        };

        let token = service.sign_eddsa(&claims).unwrap();
        // Tamper with the claims portion
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let mut claims_bytes = b64_decode(&parts[1]).unwrap();
        claims_bytes[0] ^= 0xFF; // flip some bits
        parts[1] = b64_encode(&claims_bytes);
        let tampered_token = parts.join(".");

        let result = service.verify_access_token(&tampered_token).await;
        assert!(result.is_err(), "Should reject tampered EdDSA token");
    }

    #[tokio::test]
    async fn test_eddsa_verify_rejects_rs256_token() {
        let service = JwtTokenService::new("https://test.example.com").unwrap();
        let now = service.now();
        let claims = AccessTokenClaims {
            sub: "user-mixed".to_string(),
            aud: "my-client".to_string(),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
        };

        // Sign with RS256
        let rs256_token = service.encode_jwt(&claims).unwrap();
        // Try to verify with verify_eddsa_token (which requires alg: EdDSA)
        let result: Result<AccessTokenClaims, OidcError> = service.verify_eddsa_token(&rs256_token);
        assert!(result.is_err(), "EdDSA verifier should reject RS256 token");
    }
}
