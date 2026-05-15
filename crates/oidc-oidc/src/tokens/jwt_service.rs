use ed25519_dalek::SigningKey;
use oidc_core::errors::OidcError;
use oidc_core::traits::Clock;
use oidc_core::traits::token_service::{IdTokenExtraClaims, TokenService};
use oidc_core::utils::generate_opaque_token;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// aud serde helper — serializes as a string when single value, array otherwise
// ---------------------------------------------------------------------------

mod aud_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serialize `serde_json::Value` as a string if it's a single-element array,
    /// otherwise as-is. This ensures `aud` is a string when there's just a
    /// client_id (backward compatible) and an array when resource indicators
    /// are present.
    pub fn serialize<S>(value: &serde_json::Value, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            serde_json::Value::Array(arr) if arr.len() == 1 => {
                // Single-element array: serialize as a string for backward compatibility
                if let Some(s) = arr.first().and_then(|v| v.as_str()) {
                    return serializer.serialize_str(s);
                }
                serializer.serialize_some(value)
            }
            _ => serializer.serialize_some(value),
        }
    }

    /// Deserialize `aud` which can be either a string or an array.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => {
                Ok(serde_json::Value::Array(vec![serde_json::Value::String(s)]))
            }
            other => Ok(other),
        }
    }
}

/// JWT header.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

/// Claims expected inside a client assertion JWT per RFC 7523.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientAssertionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub jti: Option<String>,
}

/// JWT claims for an access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    /// Audience — the client_id and/or resource server URIs (RFC 8707).
    /// When resource indicators are present, this becomes an array containing
    /// both the client_id and the resource URIs.
    #[serde(with = "aud_serde")]
    pub aud: serde_json::Value,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
    /// Authorized party — the client_id that was authorized (RFC 8707 §2).
    /// Required when `aud` contains resource indicators in addition to client_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// Confirmation claim for DPoP-bound tokens (RFC 9449).
    /// Contains `{"jkt": "<thumbprint>"}` when the token is sender-constrained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<serde_json::Value>,
    /// RFC 9396 RAR authorization details granted to this token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authorized party — the party to which the ID Token was issued.
    /// REQUIRED per OIDC Core §2 when `aud` contains multiple audiences;
    /// OPTIONAL otherwise. Set to `client_id` when resource indicators are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// Structured address claim (OIDC Core §5.1.1).
    /// Returned when the `address` scope is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<oidc_core::models::AddressClaim>,
    /// User roles (RBAC). Included in ID tokens when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// User groups. Included in ID tokens when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
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
    pub fn encode_jwt<Claims: Serialize>(&self, claims: &Claims) -> Result<String, OidcError> {
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

    /// Encode and sign a logout token (Back-Channel Logout §2.1).
    ///
    /// Logout tokens use the same signing infrastructure as ID tokens.
    /// We prefer RS256 for broadest compatibility with RPs.
    pub fn encode_logout_token<Claims: Serialize>(
        &self,
        claims: &Claims,
    ) -> Result<String, OidcError> {
        // Use RS256 as the primary signing algorithm for logout tokens
        self.encode_jwt(claims)
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

    /// Parse a client assertion JWT without verifying the signature.
    /// Returns `(header, claims, signing_input, signature_bytes)`.
    pub fn parse_client_assertion_unverified(
        token: &str,
    ) -> Result<(JwtHeader, ClientAssertionClaims, String, Vec<u8>), OidcError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(OidcError::InvalidClientAssertion(
                "invalid JWT format".into(),
            ));
        }
        let header_json = b64_decode(parts[0])
            .map_err(|_| OidcError::InvalidClientAssertion("invalid header encoding".into()))?;
        let header: JwtHeader = serde_json::from_slice(&header_json)
            .map_err(|_| OidcError::InvalidClientAssertion("invalid header JSON".into()))?;
        let claims_json = b64_decode(parts[1])
            .map_err(|_| OidcError::InvalidClientAssertion("invalid claims encoding".into()))?;
        let claims: ClientAssertionClaims = serde_json::from_slice(&claims_json)
            .map_err(|_| OidcError::InvalidClientAssertion("invalid claims JSON".into()))?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = b64_decode(parts[2])
            .map_err(|_| OidcError::InvalidClientAssertion("invalid signature encoding".into()))?;
        Ok((header, claims, signing_input, signature))
    }

    /// Verify a client assertion JWT (`private_key_jwt`) per RFC 7523.
    ///
    /// Validates:
    /// - `iss` == `sub` == `expected_iss` (client_id)
    /// - `aud` == `expected_aud` (token endpoint URL)
    /// - `exp` is in the future
    /// - `iat` is not too far in the future (≤ 5 minutes)
    /// - Signature verifies against a public key from the client's `jwks`
    pub fn verify_client_assertion(
        token: &str,
        jwks: &serde_json::Value,
        expected_aud: &str,
        expected_iss: &str,
        now: i64,
    ) -> Result<ClientAssertionClaims, OidcError> {
        let (header, claims, signing_input, signature) =
            Self::parse_client_assertion_unverified(token)?;

        if claims.iss != expected_iss {
            return Err(OidcError::InvalidClientAssertion(
                "iss does not match client_id".into(),
            ));
        }
        if claims.sub != expected_iss {
            return Err(OidcError::InvalidClientAssertion(
                "sub does not match client_id".into(),
            ));
        }
        if claims.aud != expected_aud {
            return Err(OidcError::InvalidClientAssertion(
                "aud does not match token endpoint".into(),
            ));
        }
        if claims.exp < now {
            return Err(OidcError::InvalidClientAssertion(
                "client assertion expired".into(),
            ));
        }
        if claims.iat > now + 300 {
            return Err(OidcError::InvalidClientAssertion(
                "client assertion issued too far in the future".into(),
            ));
        }

        let jwk = find_jwk_in_jwks(jwks, &header.kid, &header.alg)?;
        verify_signature_with_jwk(signing_input.as_bytes(), &signature, &jwk)?;

        Ok(claims)
    }

    /// Encode an access token with an `act` (actor) claim for impersonation (RFC 8693 style).
    ///
    /// The token's `sub` is the target user, and `act.sub` is the admin who is impersonating.
    /// The token is short-lived (typically 5 minutes) for security.
    pub fn encode_access_token_with_act(
        &self,
        sub: &str,
        act_sub: &str,
        scope: &str,
        audience: &[String],
        expires_in: i64,
    ) -> Result<String, OidcError> {
        let now = self.now();
        let exp = now + expires_in;
        let jti = generate_opaque_token()?;

        let claims = serde_json::json!({
            "iss": self.issuer,
            "sub": sub,
            "aud": audience,
            "exp": exp,
            "iat": now,
            "jti": jti,
            "scope": scope,
            "act": { "sub": act_sub }
        });

        self.encode_claims(&claims)
    }

    /// Encode arbitrary claims as a JWT (RS256 signed).
    fn encode_claims(&self, claims: &serde_json::Value) -> Result<String, OidcError> {
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
}

/// Load the RSA private key from `OIDC_SIGNING_KEY` env var, or generate a fresh one.
/// Find a JWK in a JWKS document by `kid` and `alg`.
pub fn find_jwk_in_jwks(
    jwks: &serde_json::Value,
    kid: &str,
    alg: &str,
) -> Result<serde_json::Value, OidcError> {
    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| OidcError::InvalidClientAssertion("jwks has no keys array".into()))?;
    for key in keys {
        let key_kid = key.get("kid").and_then(|v| v.as_str()).unwrap_or("");
        let key_alg = key.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if key_kid == kid && (key_alg == alg || key_alg.is_empty()) {
            return Ok(key.clone());
        }
    }
    Err(OidcError::InvalidClientAssertion(format!(
        "no JWK found for kid={kid} alg={alg}"
    )))
}

/// Reconstruct an RSA public key from JWK `n` and `e` (base64url-encoded big-endian integers).
fn reconstruct_rsa_public_key(n_b64: &str, e_b64: &str) -> Result<RsaPublicKey, OidcError> {
    use rsa::BigUint;
    let n_bytes =
        b64_decode(n_b64).map_err(|_| OidcError::InvalidClientAssertion("invalid RSA n".into()))?;
    let e_bytes =
        b64_decode(e_b64).map_err(|_| OidcError::InvalidClientAssertion("invalid RSA e".into()))?;
    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);
    RsaPublicKey::new(n, e)
        .map_err(|e| OidcError::InvalidClientAssertion(format!("invalid RSA key: {e}")))
}

/// Reconstruct an Ed25519 verifying key from JWK `x` (base64url-encoded 32-byte public key).
fn reconstruct_ed25519_public_key(x_b64: &str) -> Result<ed25519_dalek::VerifyingKey, OidcError> {
    let x_bytes = b64_decode(x_b64)
        .map_err(|_| OidcError::InvalidClientAssertion("invalid Ed25519 x".into()))?;
    let bytes: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| OidcError::InvalidClientAssertion("Ed25519 x must be 32 bytes".into()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| OidcError::InvalidClientAssertion("invalid Ed25519 public key".into()))
}

/// Verify a JWT signature using a single JWK value.
pub fn verify_signature_with_jwk(
    signing_input: &[u8],
    signature: &[u8],
    jwk: &serde_json::Value,
) -> Result<(), OidcError> {
    use rsa::signature::Verifier;
    let alg = jwk.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("");

    match alg {
        "RS256" => {
            let n = jwk
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidClientAssertion("RSA JWK missing n".into()))?;
            let e = jwk
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidClientAssertion("RSA JWK missing e".into()))?;
            let public_key = reconstruct_rsa_public_key(n, e)?;
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
                OidcError::InvalidClientAssertion(format!("invalid RSA signature: {e}"))
            })?;
            verifying_key.verify(signing_input, &sig).map_err(|_| {
                OidcError::InvalidClientAssertion("RSA signature verification failed".into())
            })?;
        }
        "EdDSA" => {
            use ed25519_dalek::Verifier;
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            if kty != "OKP" || crv != "Ed25519" {
                return Err(OidcError::InvalidClientAssertion(
                    "unsupported OKP curve for EdDSA".into(),
                ));
            }
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OidcError::InvalidClientAssertion("Ed25519 JWK missing x".into()))?;
            let public_key = reconstruct_ed25519_public_key(x)?;
            let sig = ed25519_dalek::Signature::try_from(signature).map_err(|e| {
                OidcError::InvalidClientAssertion(format!("invalid EdDSA signature: {e}"))
            })?;
            public_key.verify(signing_input, &sig).map_err(|_| {
                OidcError::InvalidClientAssertion("EdDSA signature verification failed".into())
            })?;
        }
        _ => {
            return Err(OidcError::InvalidClientAssertion(format!(
                "unsupported JWK alg: {alg}"
            )));
        }
    }
    Ok(())
}

/// Verify an HMAC-based JWT signature (HS256, HS384, HS512).
///
/// Uses constant-time comparison via `subtle::ConstantTimeEq` to prevent
/// timing attacks.
pub fn verify_hmac_signature(
    signing_input: &[u8],
    signature: &[u8],
    secret: &[u8],
    alg: &str,
) -> Result<(), OidcError> {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;
    type HmacSha384 = Hmac<Sha384>;
    type HmacSha512 = Hmac<Sha512>;

    match alg {
        "HS256" => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|e| OidcError::InvalidClientAssertion(format!("HMAC key error: {e}")))?;
            mac.update(signing_input);
            let expected = mac.clone().finalize().into_bytes();
            if expected[..].ct_eq(signature).into() {
                Ok(())
            } else {
                Err(OidcError::InvalidClientAssertion(
                    "HMAC signature verification failed".into(),
                ))
            }
        }
        "HS384" => {
            let mut mac = HmacSha384::new_from_slice(secret)
                .map_err(|e| OidcError::InvalidClientAssertion(format!("HMAC key error: {e}")))?;
            mac.update(signing_input);
            let expected = mac.clone().finalize().into_bytes();
            if expected[..].ct_eq(signature).into() {
                Ok(())
            } else {
                Err(OidcError::InvalidClientAssertion(
                    "HMAC signature verification failed".into(),
                ))
            }
        }
        "HS512" => {
            let mut mac = HmacSha512::new_from_slice(secret)
                .map_err(|e| OidcError::InvalidClientAssertion(format!("HMAC key error: {e}")))?;
            mac.update(signing_input);
            let expected = mac.clone().finalize().into_bytes();
            if expected[..].ct_eq(signature).into() {
                Ok(())
            } else {
                Err(OidcError::InvalidClientAssertion(
                    "HMAC signature verification failed".into(),
                ))
            }
        }
        _ => Err(OidcError::InvalidClientAssertion(format!(
            "unsupported HMAC alg: {alg}"
        ))),
    }
}

/// Verify a `client_secret_jwt` assertion per OIDC Core §9.
///
/// Unlike `verify_client_assertion` (which uses public-key / JWK verification),
/// this method verifies the HMAC signature using the client's shared secret.
pub fn verify_client_secret_jwt(
    assertion: &str,
    client_secret: &str,
    expected_aud: &str,
    expected_iss: &str,
    now: i64,
) -> Result<ClientAssertionClaims, OidcError> {
    let (header, claims, signing_input, signature) =
        JwtTokenService::parse_client_assertion_unverified(assertion)?;

    // Validate claims
    if claims.iss != expected_iss {
        return Err(OidcError::InvalidClientAssertion(
            "iss does not match client_id".into(),
        ));
    }
    if claims.sub != expected_iss {
        return Err(OidcError::InvalidClientAssertion(
            "sub does not match client_id".into(),
        ));
    }
    if claims.aud != expected_aud {
        return Err(OidcError::InvalidClientAssertion(
            "aud does not match token endpoint".into(),
        ));
    }
    if claims.exp < now {
        return Err(OidcError::InvalidClientAssertion(
            "client assertion expired".into(),
        ));
    }
    if claims.iat > now + 300 {
        return Err(OidcError::InvalidClientAssertion(
            "client assertion issued too far in the future".into(),
        ));
    }

    // alg must be an HMAC variant
    match header.alg.as_str() {
        "HS256" | "HS384" | "HS512" => {}
        other => {
            return Err(OidcError::InvalidClientAssertion(format!(
                "client_secret_jwt requires HS256/HS384/HS512, got: {other}"
            )));
        }
    }

    verify_hmac_signature(
        signing_input.as_bytes(),
        &signature,
        client_secret.as_bytes(),
        &header.alg,
    )?;

    Ok(claims)
}

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
        dpop_jkt: Option<&str>,
        authorization_details: Option<&serde_json::Value>,
        resource: Option<&[String]>,
    ) -> Result<String, OidcError> {
        let now = self.now();
        let cnf = dpop_jkt.map(|jkt| serde_json::json!({"jkt": jkt}));

        // Build `aud` per RFC 8707:
        //   - No resource indicators → aud = client_id (string, backward compatible)
        //   - Resource indicators present → aud = [client_id, resource1, resource2, ...]
        //     and azp = client_id
        let (aud, azp) = match resource {
            Some(resources) if !resources.is_empty() => {
                let mut aud_arr = vec![serde_json::Value::String(audience.to_string())];
                aud_arr.extend(
                    resources
                        .iter()
                        .map(|r| serde_json::Value::String(r.clone())),
                );
                (
                    serde_json::Value::Array(aud_arr),
                    Some(audience.to_string()),
                )
            }
            _ => (
                serde_json::Value::Array(vec![serde_json::Value::String(audience.to_string())]),
                None,
            ),
        };

        let claims = AccessTokenClaims {
            sub: subject.to_string(),
            aud,
            iss: self.issuer.clone(),
            exp: now + self.access_token_ttl_secs,
            iat: now,
            scope: scopes.join(" "),
            azp,
            cnf,
            authorization_details: authorization_details.cloned(),
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
            cnf: claims.cnf,
            authorization_details: claims.authorization_details,
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
            sid: extra.sid,
            at_hash: extra.at_hash,
            c_hash: extra.c_hash,
            email: extra.email,
            email_verified: extra.email_verified,
            name: extra.name,
            given_name: extra.given_name,
            family_name: extra.family_name,
            middle_name: extra.middle_name,
            nickname: extra.nickname,
            preferred_username: extra.preferred_username,
            profile: extra.profile,
            picture: extra.picture,
            website: extra.website,
            gender: extra.gender,
            birthdate: extra.birthdate,
            zoneinfo: extra.zoneinfo,
            locale: extra.locale,
            phone_number: extra.phone_number,
            phone_number_verified: extra.phone_number_verified,
            updated_at: extra.updated_at,
            acr: extra.acr,
            amr: extra.amr,
            azp: extra.azp,
            address: extra.address,
            roles: extra.roles,
            groups: extra.groups,
        };
        self.encode_jwt(&claims)
    }
}

pub fn b64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
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
            .issue_access_token(
                "user-123",
                "my-client",
                &["openid".to_string()],
                None,
                None,
                None,
            )
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
            aud: serde_json::json!(["my-client"]),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
            azp: None,
            cnf: None,
            authorization_details: None,
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
            aud: serde_json::json!(["my-client"]),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
            azp: None,
            cnf: None,
            authorization_details: None,
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
            .issue_access_token(
                "user-rs256",
                "my-client",
                &["openid".to_string()],
                None,
                None,
                None,
            )
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
            sid: None,
            at_hash: None,
            c_hash: None,
            email: Some("ed@example.com".to_string()),
            email_verified: Some(true),
            name: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            phone_number: None,
            phone_number_verified: None,
            updated_at: None,
            acr: None,
            amr: None,
            azp: None,
            address: None,
            roles: None,
            groups: None,
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
            aud: serde_json::json!(["my-client"]),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
            azp: None,
            cnf: None,
            authorization_details: None,
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
            aud: serde_json::json!(["my-client"]),
            iss: "https://test.example.com".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
            azp: None,
            cnf: None,
            authorization_details: None,
        };

        // Sign with RS256
        let rs256_token = service.encode_jwt(&claims).unwrap();
        // Try to verify with verify_eddsa_token (which requires alg: EdDSA)
        let result: Result<AccessTokenClaims, OidcError> = service.verify_eddsa_token(&rs256_token);
        assert!(result.is_err(), "EdDSA verifier should reject RS256 token");
    }

    // ---- private_key_jwt client assertion tests ----

    #[test]
    fn test_verify_client_assertion_ed25519_roundtrip() {
        use ed25519_dalek::Signer;
        let now = chrono::Utc::now().timestamp();

        // 1. Generate a client Ed25519 key pair
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        let verifying_key = signing_key.verifying_key();

        // 2. Build the JWKS
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "kid": "client-ed-key-1",
                "alg": "EdDSA",
                "use": "sig",
                "crv": "Ed25519",
                "x": b64_encode(&verifying_key.to_bytes())
            }]
        });

        // 3. Manually sign a client assertion JWT
        let header = serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":"client-ed-key-1"});
        let claims = serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://issuer.example.com/oidc/token",
            "exp": now + 60,
            "iat": now
        });
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = b64_encode(&signature.to_vec());
        let token = format!("{}.{}", signing_input, sig_b64);

        // 4. Verify via verify_client_assertion
        let verified = JwtTokenService::verify_client_assertion(
            &token,
            &jwks,
            "https://issuer.example.com/oidc/token",
            "client-123",
            now,
        );
        assert!(
            verified.is_ok(),
            "Expected valid client assertion: {:?}",
            verified
        );
        let verified_claims = verified.unwrap();
        assert_eq!(verified_claims.iss, "client-123");
        assert_eq!(verified_claims.sub, "client-123");
        assert_eq!(verified_claims.aud, "https://issuer.example.com/oidc/token");
    }

    #[test]
    fn test_verify_client_assertion_rsa_roundtrip() {
        use rand::rngs::OsRng;
        use rsa::pkcs1v15::SigningKey as RsaSigningKey;
        use rsa::signature::{SignatureEncoding, Signer as RsaSigner};
        let now = chrono::Utc::now().timestamp();

        // 1. Generate a client RSA key pair
        let mut rng = OsRng;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let rsa_public_key = RsaPublicKey::from(&rsa_private_key);
        let n = b64_encode(&rsa_public_key.n().to_bytes_be());
        let e = b64_encode(&rsa_public_key.e().to_bytes_be());

        // 2. Build the JWKS
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "client-rsa-key-1",
                "alg": "RS256",
                "use": "sig",
                "n": n,
                "e": e
            }]
        });

        // 3. Manually sign a client assertion JWT
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":"client-rsa-key-1"});
        let claims = serde_json::json!({
            "iss": "client-456",
            "sub": "client-456",
            "aud": "https://issuer.example.com/oidc/token",
            "exp": now + 60,
            "iat": now
        });
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(rsa_private_key);
        let signature = rsa_signing_key.sign(signing_input.as_bytes());
        let sig_b64 = b64_encode(&signature.to_vec());
        let token = format!("{}.{}", signing_input, sig_b64);

        // 4. Verify via verify_client_assertion
        let verified = JwtTokenService::verify_client_assertion(
            &token,
            &jwks,
            "https://issuer.example.com/oidc/token",
            "client-456",
            now,
        );
        assert!(
            verified.is_ok(),
            "Expected valid RSA client assertion: {:?}",
            verified
        );
        let verified_claims = verified.unwrap();
        assert_eq!(verified_claims.iss, "client-456");
    }

    #[test]
    fn test_verify_client_assertion_rejects_expired() {
        let now = chrono::Utc::now().timestamp();
        let jwks = serde_json::json!({"keys": []});

        // Craft a token with a past exp — we only care about claims validation here,
        // so the signature can be fake since exp check happens first.
        let header = serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":"x"});
        let claims = serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://issuer.example.com/oidc/token",
            "exp": now - 10,
            "iat": now - 20
        });
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let token = format!("{}.{}.fake", header_b64, claims_b64);

        let result = JwtTokenService::verify_client_assertion(
            &token,
            &jwks,
            "https://issuer.example.com/oidc/token",
            "client-123",
            now,
        );
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expired"));
    }

    #[test]
    fn test_verify_client_assertion_rejects_wrong_aud() {
        let now = chrono::Utc::now().timestamp();
        let jwks = serde_json::json!({"keys": []});

        let header = serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":"x"});
        let claims = serde_json::json!({
            "iss": "client-123",
            "sub": "client-123",
            "aud": "https://wrong.example.com/oidc/token",
            "exp": now + 60,
            "iat": now
        });
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let token = format!("{}.{}.fake", header_b64, claims_b64);

        let result = JwtTokenService::verify_client_assertion(
            &token,
            &jwks,
            "https://issuer.example.com/oidc/token",
            "client-123",
            now,
        );
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("aud"));
    }

    #[test]
    fn test_verify_client_assertion_rejects_wrong_iss() {
        let now = chrono::Utc::now().timestamp();
        let jwks = serde_json::json!({"keys": []});

        let header = serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":"x"});
        let claims = serde_json::json!({
            "iss": "client-999",
            "sub": "client-999",
            "aud": "https://issuer.example.com/oidc/token",
            "exp": now + 60,
            "iat": now
        });
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let token = format!("{}.{}.fake", header_b64, claims_b64);

        let result = JwtTokenService::verify_client_assertion(
            &token,
            &jwks,
            "https://issuer.example.com/oidc/token",
            "client-123",
            now,
        );
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("iss"));
    }

    // -----------------------------------------------------------------------
    // HMAC signature verification tests
    // -----------------------------------------------------------------------

    /// Helper: create a properly signed HMAC JWT for testing.
    fn make_hmac_jwt(alg: &str, secret: &str, claims: &serde_json::Value) -> String {
        use hmac::{Hmac, Mac};
        use sha2::{Sha256, Sha384, Sha512};

        type HmacSha256 = Hmac<Sha256>;
        type HmacSha384 = Hmac<Sha384>;
        type HmacSha512 = Hmac<Sha512>;

        let header = serde_json::json!({"alg": alg, "typ": "JWT", "kid": ""});
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        let sig_bytes = match alg {
            "HS256" => {
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(signing_input.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            "HS384" => {
                let mut mac = HmacSha384::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(signing_input.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            "HS512" => {
                let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(signing_input.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            _ => panic!("unsupported alg in test helper: {alg}"),
        };

        format!("{}.{}", signing_input, b64_encode(&sig_bytes))
    }

    #[test]
    fn test_verify_hmac_signature_hs256_valid() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let secret = b"my-secret-key";
        let signing_input = b"header.payload";
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(signing_input);
        let sig = mac.finalize().into_bytes();

        assert!(verify_hmac_signature(signing_input, &sig, secret, "HS256").is_ok());
    }

    #[test]
    fn test_verify_hmac_signature_hs384_valid() {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;

        type HmacSha384 = Hmac<Sha384>;

        let secret = b"my-secret-key";
        let signing_input = b"header.payload";
        let mut mac = HmacSha384::new_from_slice(secret).unwrap();
        mac.update(signing_input);
        let sig = mac.finalize().into_bytes();

        assert!(verify_hmac_signature(signing_input, &sig, secret, "HS384").is_ok());
    }

    #[test]
    fn test_verify_hmac_signature_hs512_valid() {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let secret = b"my-secret-key";
        let signing_input = b"header.payload";
        let mut mac = HmacSha512::new_from_slice(secret).unwrap();
        mac.update(signing_input);
        let sig = mac.finalize().into_bytes();

        assert!(verify_hmac_signature(signing_input, &sig, secret, "HS512").is_ok());
    }

    #[test]
    fn test_verify_hmac_signature_wrong_secret() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let secret = b"correct-secret";
        let signing_input = b"header.payload";
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(signing_input);
        let sig = mac.finalize().into_bytes();

        let result = verify_hmac_signature(signing_input, &sig, b"wrong-secret", "HS256");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("HMAC signature verification failed"));
    }

    #[test]
    fn test_verify_hmac_signature_wrong_signing_input() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let secret = b"my-secret-key";
        let signing_input = b"header.payload";
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(signing_input);
        let sig = mac.finalize().into_bytes();

        let result = verify_hmac_signature(b"header.tampered", &sig, secret, "HS256");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hmac_signature_unsupported_alg() {
        let result = verify_hmac_signature(b"data", b"sig", b"key", "HS123");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("unsupported HMAC alg"));
    }

    #[test]
    fn test_verify_client_secret_jwt_hs256_roundtrip() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now
        });

        let token = make_hmac_jwt("HS256", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.iss, expected_iss);
        assert_eq!(verified.sub, expected_iss);
        assert_eq!(verified.aud, expected_aud);
    }

    #[test]
    fn test_verify_client_secret_jwt_hs384_roundtrip() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now
        });

        let token = make_hmac_jwt("HS384", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_client_secret_jwt_hs512_roundtrip() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now
        });

        let token = make_hmac_jwt("HS512", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_client_secret_jwt_rejects_wrong_secret() {
        let now = chrono::Utc::now().timestamp();
        let secret = "correct-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now
        });

        let token = make_hmac_jwt("HS256", secret, &claims);

        let result =
            verify_client_secret_jwt(&token, "wrong-secret", expected_aud, expected_iss, now);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("HMAC signature verification failed"));
    }

    #[test]
    fn test_verify_client_secret_jwt_rejects_expired() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now - 10,
            "iat": now - 60
        });

        let token = make_hmac_jwt("HS256", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expired"));
    }

    #[test]
    fn test_verify_client_secret_jwt_rejects_wrong_aud() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": "https://wrong.example.com/token",
            "exp": now + 300,
            "iat": now
        });

        let token = make_hmac_jwt("HS256", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("aud"));
    }

    #[test]
    fn test_verify_client_secret_jwt_rejects_wrong_iss() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": "client-999",
            "sub": "client-999",
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now
        });

        let token = make_hmac_jwt("HS256", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("iss"));
    }

    #[test]
    fn test_verify_client_secret_jwt_rejects_non_hmac_alg() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        // Build a JWT with alg=RS256 (not HMAC)
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": ""});
        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now + 300,
            "iat": now
        });
        let header_b64 = b64_encode(header.to_string().as_bytes());
        let claims_b64 = b64_encode(claims.to_string().as_bytes());
        let token = format!("{}.{}.fake-sig", header_b64, claims_b64);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err())
                .contains("client_secret_jwt requires HS256/HS384/HS512")
        );
    }

    #[test]
    fn test_verify_client_secret_jwt_rejects_future_iat() {
        let now = chrono::Utc::now().timestamp();
        let secret = "shared-client-secret";
        let expected_iss = "client-abc";
        let expected_aud = "https://issuer.example.com/oidc/token";

        let claims = serde_json::json!({
            "iss": expected_iss,
            "sub": expected_iss,
            "aud": expected_aud,
            "exp": now + 1000,
            "iat": now + 600  // > now + 300
        });

        let token = make_hmac_jwt("HS256", secret, &claims);

        let result = verify_client_secret_jwt(&token, secret, expected_aud, expected_iss, now);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("future"));
    }
}
