//! Pure-Rust key generation for realm signing keys (WASM-compatible).

use oidc_core::OidcError;
use oidc_core::models::RealmSigningKeys;
use pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey};

/// Generate a fresh RSA 2048 + Ed25519 keypair for a realm.
///
/// Uses pure-Rust crypto (no OpenSSL shell), so it works in both native
/// and WASI Preview 2 targets.
pub fn generate_realm_keys(realm_id: uuid::Uuid) -> Result<RealmSigningKeys, OidcError> {
    let mut rng = OsRng;

    // RSA 2048
    let rsa_private = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| OidcError::Internal(format!("RSA key generation failed: {e}")))?;
    let rsa_public = RsaPublicKey::from(&rsa_private);

    let rsa_private_pem = rsa_private
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| OidcError::Internal(format!("RSA PEM encoding failed: {e}")))?
        .to_string();

    let rsa_public_n = b64_encode(&rsa_public.n().to_bytes_be());
    let rsa_public_e = b64_encode(&rsa_public.e().to_bytes_be());

    // Ed25519
    let ed_secret: [u8; 32] = rand::random();
    let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_secret);
    let ed_verifying = ed_signing.verifying_key();

    let ed_private_pem = ed_signing
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| OidcError::Internal(format!("Ed25519 PEM encoding failed: {e}")))?
        .to_string();

    let ed_public_x = b64_encode(&ed_verifying.to_bytes());

    let now = chrono::Utc::now();

    Ok(RealmSigningKeys {
        realm_id,
        rsa_private_pem,
        rsa_kid: "key-1".to_string(),
        rsa_public_n,
        rsa_public_e,
        ed25519_private_pem: ed_private_pem,
        ed25519_kid: "ed-key-1".to_string(),
        ed25519_public_x: ed_public_x,
        created_at: now,
        updated_at: now,
    })
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_realm_keys() {
        let realm_id = uuid::Uuid::now_v7();
        let keys = generate_realm_keys(realm_id).unwrap();

        assert_eq!(keys.realm_id, realm_id);
        assert!(keys.rsa_private_pem.contains("BEGIN RSA PRIVATE KEY"));
        assert!(!keys.rsa_public_n.is_empty());
        assert!(!keys.rsa_public_e.is_empty());
        assert!(keys.ed25519_private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!keys.ed25519_public_x.is_empty());

        // Verify PEMs can be parsed back
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let _ = RsaPrivateKey::from_pkcs1_pem(&keys.rsa_private_pem).unwrap();

        use pkcs8::DecodePrivateKey;
        let _ = ed25519_dalek::SigningKey::from_pkcs8_pem(&keys.ed25519_private_pem).unwrap();
    }
}
