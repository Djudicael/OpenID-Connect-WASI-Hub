//! JWE (JSON Web Encryption) utilities for encrypting and decrypting ID tokens.
//!
//! Supports:
//! - `dir` algorithm with A256GCM content encryption (shared symmetric key)
//! - `RSA-OAEP-256` algorithm with A256GCM content encryption (RSA key wrapping)
//!
//! JWE compact serialization format:
//! `base64url(header).base64url(encrypted_key).base64url(iv).base64url(ciphertext).base64url(auth_tag)`

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
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
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| OidcError::Internal(e.to_string()))?);

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

/// Decrypt a JWE compact serialization using `dir` algorithm (direct symmetric key) with A256GCM.
///
/// The key must be exactly 32 bytes (for A256GCM).
/// Returns the decrypted plaintext as a UTF-8 string.
pub fn decrypt_jwe_dir(jwe: &str, symmetric_key: &[u8]) -> Result<String, OidcError> {
    if symmetric_key.len() != 32 {
        return Err(OidcError::InvalidInput(
            "JWE dir key must be 32 bytes".into(),
        ));
    }

    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(OidcError::InvalidInput(
            "JWE compact serialization must have 5 parts".into(),
        ));
    }

    // Decode and verify header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE header JSON: {e}")))?;

    if header["alg"] != "dir" {
        return Err(OidcError::InvalidInput(format!(
            "JWE alg mismatch: expected 'dir', got '{}'",
            header["alg"]
        )));
    }
    if header["enc"] != "A256GCM" {
        return Err(OidcError::InvalidInput(format!(
            "JWE enc mismatch: expected 'A256GCM', got '{}'",
            header["enc"]
        )));
    }

    // For dir, encrypted_key (part 1) must be empty
    if !parts[1].is_empty() {
        return Err(OidcError::InvalidInput(
            "JWE dir algorithm requires empty encrypted_key".into(),
        ));
    }

    // Decode IV (nonce)
    let iv_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE IV base64: {e}")))?;
    if iv_bytes.len() != 12 {
        return Err(OidcError::InvalidInput(format!(
            "JWE IV must be 12 bytes, got {}",
            iv_bytes.len()
        )));
    }

    // Decode ciphertext
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE ciphertext base64: {e}")))?;

    // Decode auth tag
    let tag_bytes = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE auth tag base64: {e}")))?;
    if tag_bytes.len() != 16 {
        return Err(OidcError::InvalidInput(format!(
            "JWE auth tag must be 16 bytes, got {}",
            tag_bytes.len()
        )));
    }

    // Reconstruct ciphertext + tag for AES-GCM decryption
    let mut ciphertext_with_tag = Vec::with_capacity(ct_bytes.len() + tag_bytes.len());
    ciphertext_with_tag.extend_from_slice(&ct_bytes);
    ciphertext_with_tag.extend_from_slice(&tag_bytes);

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(symmetric_key)
        .map_err(|e| OidcError::Internal(format!("AES key error: {e}")))?;
    let nonce = Nonce::from_slice(&iv_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| OidcError::Internal(format!("AES-GCM decrypt error: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| OidcError::Internal(format!("Decrypted payload is not valid UTF-8: {e}")))
}

/// Encrypt a payload using JWE with RSA-OAEP-256 key wrapping and A256GCM content encryption.
///
/// The RSA public key must be in PEM format.
pub fn encrypt_jwe_rsa_oaep_256(
    payload: &str,
    rsa_public_key_pem: &str,
) -> Result<String, OidcError> {
    let header = json!({
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM",
        "typ": "JWT"
    });
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| OidcError::Internal(e.to_string()))?);

    // Generate random CEK (content encryption key) — 32 bytes for A256GCM
    let cek: [u8; 32] = rand::thread_rng().r#gen();

    // Encrypt CEK with RSA-OAEP-256
    let public_key = RsaPublicKey::from_public_key_pem(rsa_public_key_pem)
        .map_err(|e| OidcError::InvalidInput(format!("Invalid RSA public key PEM: {e}")))?;
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

/// Decrypt a JWE compact serialization using RSA-OAEP-256 key wrapping with A256GCM content encryption.
///
/// The RSA private key must be in PEM format.
/// Returns the decrypted plaintext as a UTF-8 string.
pub fn decrypt_jwe_rsa_oaep_256(jwe: &str, rsa_private_key_pem: &str) -> Result<String, OidcError> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(OidcError::InvalidInput(
            "JWE compact serialization must have 5 parts".into(),
        ));
    }

    // Decode and verify header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE header JSON: {e}")))?;

    if header["alg"] != "RSA-OAEP-256" {
        return Err(OidcError::InvalidInput(format!(
            "JWE alg mismatch: expected 'RSA-OAEP-256', got '{}'",
            header["alg"]
        )));
    }
    if header["enc"] != "A256GCM" {
        return Err(OidcError::InvalidInput(format!(
            "JWE enc mismatch: expected 'A256GCM', got '{}'",
            header["enc"]
        )));
    }

    // Decode encrypted CEK
    let encrypted_cek = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE encrypted key base64: {e}")))?;

    // Decrypt CEK using RSA-OAEP-256
    let private_key = RsaPrivateKey::from_pkcs8_pem(rsa_private_key_pem)
        .map_err(|e| OidcError::InvalidInput(format!("Invalid RSA private key PEM: {e}")))?;
    let cek = private_key
        .decrypt(Oaep::new::<Sha256>(), &encrypted_cek)
        .map_err(|e| OidcError::Internal(format!("RSA-OAEP-256 decryption error: {e}")))?;

    // Decode IV (nonce)
    let iv_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE IV base64: {e}")))?;
    if iv_bytes.len() != 12 {
        return Err(OidcError::InvalidInput(format!(
            "JWE IV must be 12 bytes, got {}",
            iv_bytes.len()
        )));
    }

    // Decode ciphertext
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE ciphertext base64: {e}")))?;

    // Decode auth tag
    let tag_bytes = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE auth tag base64: {e}")))?;
    if tag_bytes.len() != 16 {
        return Err(OidcError::InvalidInput(format!(
            "JWE auth tag must be 16 bytes, got {}",
            tag_bytes.len()
        )));
    }

    // Reconstruct ciphertext + tag for AES-GCM decryption
    let mut ciphertext_with_tag = Vec::with_capacity(ct_bytes.len() + tag_bytes.len());
    ciphertext_with_tag.extend_from_slice(&ct_bytes);
    ciphertext_with_tag.extend_from_slice(&tag_bytes);

    // Decrypt with AES-256-GCM using the CEK
    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| OidcError::Internal(format!("AES key error: {e}")))?;
    let nonce = Nonce::from_slice(&iv_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| OidcError::Internal(format!("AES-GCM decrypt error: {e}")))?;

    String::from_utf8(plaintext)
        .map_err(|e| OidcError::Internal(format!("Decrypted payload is not valid UTF-8: {e}")))
}

/// Decrypt a JWE compact serialization by inspecting the header and dispatching
/// to the appropriate decryption function.
///
/// Provide `symmetric_key` for `dir` algorithm, or `rsa_private_key_pem` for `RSA-OAEP-256`.
/// Returns an error if the required key material is not provided for the detected algorithm.
pub fn decrypt_jwe(
    jwe: &str,
    symmetric_key: Option<&[u8]>,
    rsa_private_key_pem: Option<&str>,
) -> Result<String, OidcError> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(OidcError::InvalidInput(
            "JWE compact serialization must have 5 parts".into(),
        ));
    }

    // Decode header to determine algorithm
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OidcError::InvalidInput(format!("Invalid JWE header JSON: {e}")))?;

    let alg = header["alg"]
        .as_str()
        .ok_or_else(|| OidcError::InvalidInput("JWE header missing 'alg' field".into()))?;

    match alg {
        "dir" => {
            let key = symmetric_key.ok_or_else(|| {
                OidcError::InvalidInput("JWE dir algorithm requires a symmetric key".into())
            })?;
            decrypt_jwe_dir(jwe, key)
        }
        "RSA-OAEP-256" => {
            let pem = rsa_private_key_pem.ok_or_else(|| {
                OidcError::InvalidInput(
                    "JWE RSA-OAEP-256 algorithm requires an RSA private key PEM".into(),
                )
            })?;
            decrypt_jwe_rsa_oaep_256(jwe, pem)
        }
        _ => Err(OidcError::InvalidInput(format!(
            "Unsupported JWE alg: {alg}. Supported: dir, RSA-OAEP-256"
        ))),
    }
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
                OidcError::InvalidInput("JWE RSA-OAEP-256 requires an RSA public key PEM".into())
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

    /// Generate an RSA-2048 key pair for testing.
    fn generate_rsa_keypair() -> (RsaPrivateKey, String, String) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();

        let private_pem =
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&private_key, rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string();
        let public_pem =
            rsa::pkcs8::EncodePublicKey::to_public_key_pem(&public_key, rsa::pkcs8::LineEnding::LF)
                .unwrap();

        (private_key, private_pem, public_pem)
    }

    // ---- Encryption-only tests (existing) ----

    #[test]
    fn test_encrypt_jwe_dir_round_trip_format() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let jwe = encrypt_jwe_dir("hello world", &key).unwrap();

        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(
            parts.len(),
            5,
            "JWE compact serialization must have 5 parts"
        );
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
        let header_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
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
        let result = encrypt_id_token_if_configured("token", Some("RSA1_5"), None, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("Unsupported JWE alg")));
    }

    #[test]
    fn test_encrypt_id_token_if_configured_dir_missing_key() {
        let result = encrypt_id_token_if_configured("token", Some("dir"), None, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("symmetric key")));
    }

    #[test]
    fn test_encrypt_id_token_if_configured_rsa_missing_pem() {
        let result =
            encrypt_id_token_if_configured("token", Some("RSA-OAEP-256"), None, None, None);
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
        assert_ne!(jwe1, jwe2);
    }

    #[test]
    fn test_encrypt_jwe_dir_same_key_different_ivs() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let jwe1 = encrypt_jwe_dir("same payload", &key).unwrap();
        let jwe2 = encrypt_jwe_dir("same payload", &key).unwrap();
        assert_ne!(jwe1, jwe2);
    }

    // ---- Decryption round-trip tests ----

    #[test]
    fn test_decrypt_jwe_dir_round_trip() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let payload = "hello world";
        let jwe = encrypt_jwe_dir(payload, &key).unwrap();
        let decrypted = decrypt_jwe_dir(&jwe, &key).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_dir_round_trip_empty_payload() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let payload = "";
        let jwe = encrypt_jwe_dir(payload, &key).unwrap();
        let decrypted = decrypt_jwe_dir(&jwe, &key).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_dir_round_trip_json_payload() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;
        let jwe = encrypt_jwe_dir(payload, &key).unwrap();
        let decrypted = decrypt_jwe_dir(&jwe, &key).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_dir_wrong_key_fails() {
        let key1: [u8; 32] = rand::thread_rng().r#gen();
        let key2: [u8; 32] = rand::thread_rng().r#gen();
        let jwe = encrypt_jwe_dir("secret data", &key1).unwrap();
        let result = decrypt_jwe_dir(&jwe, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_jwe_dir_rejects_wrong_key_length() {
        let short_key = [0u8; 16];
        let result = decrypt_jwe_dir("a.b.c.d.e", &short_key);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("32 bytes")));
    }

    #[test]
    fn test_decrypt_jwe_dir_rejects_malformed_jwe() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let result = decrypt_jwe_dir("not.enough.parts", &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_jwe_dir_rejects_wrong_alg() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        // Encrypt with dir, then tamper the header to say RSA-OAEP-256
        let jwe = encrypt_jwe_dir("test", &key).unwrap();
        let parts: Vec<&str> = jwe.split('.').collect();
        let fake_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg": "RSA-OAEP-256", "enc": "A256GCM"})).unwrap());
        let tampered_jwe = format!(
            "{}.{}.{}.{}.{}",
            fake_header, parts[1], parts[2], parts[3], parts[4]
        );
        let result = decrypt_jwe_dir(&tampered_jwe, &key);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("alg mismatch")));
    }

    #[test]
    fn test_decrypt_jwe_rsa_oaep_256_round_trip() {
        let (_priv_key, private_pem, public_pem) = generate_rsa_keypair();
        let payload = "hello RSA world";
        let jwe = encrypt_jwe_rsa_oaep_256(payload, &public_pem).unwrap();
        let decrypted = decrypt_jwe_rsa_oaep_256(&jwe, &private_pem).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_rsa_oaep_256_round_trip_empty_payload() {
        let (_priv_key, private_pem, public_pem) = generate_rsa_keypair();
        let payload = "";
        let jwe = encrypt_jwe_rsa_oaep_256(payload, &public_pem).unwrap();
        let decrypted = decrypt_jwe_rsa_oaep_256(&jwe, &private_pem).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_rsa_oaep_256_round_trip_json_payload() {
        let (_priv_key, private_pem, public_pem) = generate_rsa_keypair();
        let payload = r#"{"sub":"1234567890","name":"Jane Doe","iat":1516239022}"#;
        let jwe = encrypt_jwe_rsa_oaep_256(payload, &public_pem).unwrap();
        let decrypted = decrypt_jwe_rsa_oaep_256(&jwe, &private_pem).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_rsa_oaep_256_wrong_key_fails() {
        let mut rng = rand::thread_rng();
        let private_key_1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_key_2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_pem_1 = rsa::pkcs8::EncodePublicKey::to_public_key_pem(
            &private_key_1.to_public_key(),
            rsa::pkcs8::LineEnding::LF,
        )
        .unwrap();
        let private_pem_2 =
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&private_key_2, rsa::pkcs8::LineEnding::LF)
                .unwrap();

        let jwe = encrypt_jwe_rsa_oaep_256("secret", &public_pem_1).unwrap();
        let result = decrypt_jwe_rsa_oaep_256(&jwe, &private_pem_2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_jwe_rsa_oaep_256_rejects_malformed_jwe() {
        let (_priv_key, private_pem, _public_pem) = generate_rsa_keypair();
        let result = decrypt_jwe_rsa_oaep_256("not.enough.parts", &private_pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_jwe_rsa_oaep_256_rejects_wrong_alg() {
        let (_priv_key, private_pem, public_pem) = generate_rsa_keypair();
        let jwe = encrypt_jwe_rsa_oaep_256("test", &public_pem).unwrap();
        let parts: Vec<&str> = jwe.split('.').collect();
        let fake_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg": "dir", "enc": "A256GCM"})).unwrap());
        let tampered_jwe = format!(
            "{}.{}.{}.{}.{}",
            fake_header, parts[1], parts[2], parts[3], parts[4]
        );
        let result = decrypt_jwe_rsa_oaep_256(&tampered_jwe, &private_pem);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("alg mismatch")));
    }

    // ---- Orchestrator (decrypt_jwe) tests ----

    #[test]
    fn test_decrypt_jwe_dispatches_dir() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let payload = "dispatch test dir";
        let jwe = encrypt_jwe_dir(payload, &key).unwrap();
        let decrypted = decrypt_jwe(&jwe, Some(&key), None).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_dispatches_rsa_oaep_256() {
        let (_priv_key, private_pem, public_pem) = generate_rsa_keypair();
        let payload = "dispatch test rsa";
        let jwe = encrypt_jwe_rsa_oaep_256(payload, &public_pem).unwrap();
        let decrypted = decrypt_jwe(&jwe, None, Some(&private_pem)).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_decrypt_jwe_dir_missing_key() {
        let key: [u8; 32] = rand::thread_rng().r#gen();
        let jwe = encrypt_jwe_dir("test", &key).unwrap();
        let result = decrypt_jwe(&jwe, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("symmetric key")));
    }

    #[test]
    fn test_decrypt_jwe_rsa_missing_pem() {
        let (_priv_key, _private_pem, public_pem) = generate_rsa_keypair();
        let jwe = encrypt_jwe_rsa_oaep_256("test", &public_pem).unwrap();
        let result = decrypt_jwe(&jwe, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("RSA private key PEM")));
    }

    #[test]
    fn test_decrypt_jwe_unsupported_alg() {
        let fake_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg": "RSA1_5", "enc": "A256GCM"})).unwrap());
        let fake_jwe = format!("{fake_header}.key.iv.ct.tag");
        let result = decrypt_jwe(&fake_jwe, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput(ref s) if s.contains("Unsupported JWE alg")));
    }

    #[test]
    fn test_decrypt_jwe_malformed() {
        let result = decrypt_jwe("not.enough.parts", None, None);
        assert!(result.is_err());
    }
}
