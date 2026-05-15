//! JWE (JSON Web Encryption) utilities for encrypting ID tokens.
//!
//! Supports:
//! - `dir` algorithm with A256GCM content encryption (shared symmetric key)
//! - `RSA-OAEP-256` algorithm with A256GCM content encryption (RSA key wrapping)
//!
//! JWE compact serialization format:
//! `base64url(header).base64url(encrypted_key).base64url(iv).base64url(ciphertext).base64url(auth_tag)`

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::Oaep;
use rsa::RsaPublicKey;
use serde_json::json;

use crate::OidcError;

/// Encrypt a payload using JWE with `dir` algorithm (direct symmetric key).
///
/// The key must be exactly 32 bytes (for A256GCM).
/// Returns the compact JWE serialization.
pub fn encrypt_jwe_dir(payload: &str, symmetric_key: &[u8]) -> Result<String, OidcError> {
    if symmetric_key.len() != 32 {
        return Err(OidcError::InvalidInput(
            "JWE dir key must be 32 bytes".into(),
        ));
    }

    let header = json!({
        "alg": "dir",
        "enc": "A256GCM",
        "typ": "JWT"
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| OidcError::Internal(e.to_string()))?,
    );

    // Generate random IV (96 bits for GCM)
    let iv: [u8; 12] = rand::thread_rng().r#gen();
    let iv_b64 = URL_SAFE_NO_PAD.encode(iv);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(symmetric_key)
        .map_err(|e| OidcError::Internal(format!("AES key error: {e}")))?;
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, payload.as_bytes())
        .map_err(|e| OidcError::Internal(format!("AES-GCM encrypt error: {e}")))?;

    // ciphertext from aes-gcm includes the tag appended (last 16 bytes)
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let ct_b64 = URL_SAFE_NO_PAD.encode(ct);
    let tag_b64 = URL_SAFE_NO_PAD.encode(tag);

    // dir: encrypted_key is empty
    Ok(format!("{header_b64}..{iv_b64}.{ct_b64}.{tag_b64}"))
}

/// Encrypt a payload using JWE with RSA-OAEP-256 key wrapping and A256GCM content encryption.
///
/// The RSA public key must be in PEM format.
pub fn encrypt_jwe_rsa_oaep_256(payload: &str, rsa_public_key_pem: &str) -> Result<String, OidcError> {
    let header = json!({
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM",
        "typ": "JWT"
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| OidcError::Internal(e.to_string()))?,
    );

    // Generate random CEK (content encryption key) — 32 bytes for A256GCM
    let cek: [u8; 32] = rand::thread_rng().r#gen();

    // Encrypt CEK with RSA-OAEP-256
    let public_key = RsaPublicKey::from_public_key_pem(rsa_public_key_pem).map_err(|e| {
        OidcError::InvalidInput(format!("Invalid RSA public key PEM: {e}"))
    })?;
    let mut rng = rand::thread_rng();
    let encrypted_cek = public_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &cek)
        .map_err(|e| OidcError::Internal(format!("RSA encryption error: {e}")))?;
    let encrypted_key_b64 = URL_SAFE_NO_PAD.encode(&encrypted_cek);

    // Generate random IV
    let iv: [u8; 12] = rand::thread_rng().r#gen();
    let iv_b64 = URL_SAFE_NO_PAD.encode(iv);

    // Encrypt payload with AES-256-GCM using CEK
    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| OidcError::Internal(format!("AES key error: {e}")))?;
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, payload.as_bytes())
        .map_err(|e| OidcError::Internal(format!("AES-GCM encrypt error: {e}")))?;

    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let ct_b64 = URL_SAFE_NO_PAD.encode(ct);
    let tag_b64 = URL_SAFE_NO_PAD.encode(tag);

    Ok(format!(
        "{header_b64}.{encrypted_key_b64}.{iv_b64}.{ct_b64}.{tag_b64}"
    ))
}

/// Encrypt a JWT payload using the client's configured encryption settings.
///
/// Returns `Ok(None)` if the client doesn't have encryption configured (meaning the
/// payload should be returned as a regular signed JWT, not encrypted).
/// Returns `Ok(Some(jwe_string))` if encryption was applied.
pub fn encrypt_id_token_if_configured(
    signed_id_token: &str,
    enc_alg: Option<&str>,
    enc_enc: Option<&str>,
    enc_key: Option<&[u8]>,
    enc_key_pem: Option<&str>,
) -> Result<Option<String>, OidcError> {
    let alg = match enc_alg {
        Some(a) => a,
        None => return Ok(None),
    };

    // Verify enc is A256GCM (only supported content encryption)
    if let Some(enc) = enc_enc {
        if enc != "A256GCM" {
            return Err(OidcError::InvalidInput(format!(
                "Unsupported JWE enc: {enc}. Only A256GCM is supported."
            )));
        }
    }

    match alg {
        "dir" => {
            let key = enc_key.ok_or_else(|| {
                OidcError::InvalidInput("JWE dir requires a symmetric key".into())
            })?;
            Ok(Some(encrypt_jwe_dir(signed_id_token, key)?))
        }
        "RSA-OAEP-256" => {
            let pem = enc_key_pem.ok_or_else(|| {
                OidcError::InvalidInput(
                    "JWE RSA-OAEP-256 requires an RSA public key PEM".into(),
                )
            })?;
            Ok(Some(encrypt_jwe_rsa_oaep_256(signed_id_token, pem)?))
        }
        _ => Err(OidcError::InvalidInput(format!(
            "Unsupported JWE alg: {alg}. Supported: dir, RSA-OAEP-256"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_jwe_dir_round_trip_format() {
        // We can't easily decrypt in this test (no JWE decryptor here),
        // but we can verify the format is correct: 5 dot-separated parts,
        // with the second part (encrypted_key) being empty for "dir".
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let jwe = encrypt_jwe_dir("hello world", &key).unwrap();

        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(parts.len(), 5, "JWE compact serialization must have 5 parts");
        assert!(!parts[0].is_empty(), "header must not be empty");
        assert!(parts[1].is_empty(), "encrypted_key must be empty for dir");
        assert!(!parts[2].is_empty(), "iv must not be empty");
        assert!(!parts[3].is_empty(), "ciphertext must not be empty");
        assert!(!parts[4].is_empty(), "tag must not be empty");
    }

    #[test]
    fn test_encrypt_jwe_dir_rejects_wrong_key_length() {
        let short_key = [0u8; 16];
        let result = encrypt_jwe_dir("test", &short_key);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("32 bytes")));
    }

    #[test]
    fn test_encrypt_jwe_dir_header_contains_alg_dir() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let jwe = encrypt_jwe_dir("payload", &key).unwrap();
        let header_b64 = jwe.split('.').next().unwrap();
        let header_json: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(header_b64).unwrap(),
        )
        .unwrap();
        assert_eq!(header_json["alg"], "dir");
        assert_eq!(header_json["enc"], "A256GCM");
        assert_eq!(header_json["typ"], "JWT");
    }

    #[test]
    fn test_encrypt_id_token_if_configured_returns_none_when_no_alg() {
        let result = encrypt_id_token_if_configured("token", None, None, None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_encrypt_id_token_if_configured_unsupported_enc() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let result = encrypt_id_token_if_configured(
            "token",
            Some("dir"),
            Some("A128CBC-HS256"),
            Some(&key),
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("Unsupported JWE enc")));
    }

    #[test]
    fn test_encrypt_id_token_if_configured_unsupported_alg() {
        let result = encrypt_id_token_if_configured(
            "token",
            Some("RSA1_5"),
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("Unsupported JWE alg")));
    }

    #[test]
    fn test_encrypt_id_token_if_configured_dir_missing_key() {
        let result = encrypt_id_token_if_configured(
            "token",
            Some("dir"),
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("symmetric key")));
    }

    #[test]
    fn test_encrypt_id_token_if_configured_rsa_missing_pem() {
        let result = encrypt_id_token_if_configured(
            "token",
            Some("RSA-OAEP-256"),
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("RSA public key PEM")));
    }

    #[test]
    fn test_encrypt_jwe_dir_different_keys_produce_different_ciphertexts() {
        let key1: [u8; 32] = rand::thread_rng().r#gen();
        let key2: [u8; 32] = rand::thread_rng().r#gen();
        let jwe1 = encrypt_jwe_dir("same payload", &key1).unwrap();
        let jwe2 = encrypt_jwe_dir("same payload", &key2).unwrap();
        // Different keys should produce different ciphertexts
        assert_ne!(jwe1, jwe2);
    }

    #[test]
    fn test_encrypt_jwe_dir_same_key_different_ivs() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let jwe1 = encrypt_jwe_dir("same payload", &key).unwrap();
        let jwe2 = encrypt_jwe_dir("same payload", &key).unwrap();
        // Same key + same payload but different IVs should produce different ciphertexts
        assert_ne!(jwe1, jwe2);
    }
}
