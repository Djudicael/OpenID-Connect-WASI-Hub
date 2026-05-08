//! Encrypted KeyPackage storage.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use oidc_core::OidcError;
use oidc_core::models::mls::KeyPackageEntry;
use oidc_repository::Connection;
use sha2::Sha256;
use uuid::Uuid;

/// Static encryption key material for KeyPackages at rest.
/// In production this should come from env/secrets, not hardcoded.
const KP_MASTER_SECRET: &[u8] = b"oidc-mls-key-package-key";
const KP_SALT: &[u8] = b"oidc-mls-salt";

/// Store for MLS KeyPackages.
pub struct KeyPackageStore;

impl KeyPackageStore {
    /// Derive an AES-256-GCM key from the master secret.
    fn derive_key() -> Result<Key<Aes256Gcm>, OidcError> {
        let hk = Hkdf::<Sha256>::new(Some(KP_SALT), KP_MASTER_SECRET);
        let mut okm = [0u8; 32];
        hk.expand(b"oidc-mls-kp-enc", &mut okm)
            .map_err(|e| OidcError::Internal(format!("hkdf: {e}")))?;
        Ok(*Key::<Aes256Gcm>::from_slice(&okm))
    }

    /// Encrypt key package data with AES-256-GCM.
    fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OidcError> {
        let key = Self::derive_key()?;
        let cipher = Aes256Gcm::new(&key);

        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| OidcError::Internal(format!("getrandom: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| OidcError::Internal(format!("encrypt: {e}")))?;

        let mut combined = ciphertext;
        combined.extend_from_slice(&nonce_bytes);
        Ok((combined, nonce_bytes.to_vec()))
    }

    /// Decrypt key package data.
    fn decrypt(combined: &[u8]) -> Result<Vec<u8>, OidcError> {
        if combined.len() < 12 {
            return Err(OidcError::Internal("invalid encrypted data".into()));
        }
        let (ciphertext, nonce_bytes) = combined.split_at(combined.len() - 12);
        let key = Self::derive_key()?;
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| OidcError::Internal(format!("decrypt: {e}")))
    }

    /// Store a new KeyPackage.
    pub async fn store(
        conn: &mut Connection,
        user_id: Uuid,
        key_package_data: Vec<u8>,
    ) -> Result<KeyPackageEntry, OidcError> {
        let id = oidc_core::utils::generate_uuid_v7();
        let key_package_ref = sha2_256(&key_package_data);
        let (encrypted, _nonce) = Self::encrypt(&key_package_data)?;
        let created_at = chrono::Utc::now();

        let sql = r#"
            INSERT INTO mls_key_packages (id, user_id, key_package_ref, key_package_encrypted, created_at)
            VALUES ($1, $2, $3, $4, $5)
        "#;
        conn.execute_params(
            sql,
            &[&id, &user_id, &key_package_ref, &encrypted, &created_at],
        )
        .await
        .map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(KeyPackageEntry {
            id,
            user_id,
            key_package_ref,
            key_package_encrypted: encrypted,
            used: false,
            created_at,
            expires_at: None,
        })
    }

    /// Retrieve a KeyPackage by its reference.
    pub async fn get_by_ref(
        conn: &mut Connection,
        key_package_ref: &[u8],
    ) -> Result<Option<KeyPackageEntry>, OidcError> {
        let sql = r#"
            SELECT id, user_id, key_package_ref, key_package_encrypted, used, created_at, expires_at
            FROM mls_key_packages
            WHERE key_package_ref = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&key_package_ref])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;

        Ok(row.map(|r| {
            let id: Uuid = r.get(0).unwrap();
            let user_id: Uuid = r.get(1).unwrap();
            let key_package_ref: Vec<u8> = r.get(2).unwrap();
            let key_package_encrypted: Vec<u8> = r.get(3).unwrap();
            let used: bool = r.get(4).unwrap();
            let created_at: chrono::DateTime<chrono::Utc> = r.get(5).unwrap();
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = r.get(6).unwrap();
            KeyPackageEntry {
                id,
                user_id,
                key_package_ref,
                key_package_encrypted,
                used,
                created_at,
                expires_at,
            }
        }))
    }

    /// Mark a KeyPackage as used.
    pub async fn mark_used(conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE mls_key_packages SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(|e| OidcError::Internal(e.to_string()))?;
        Ok(())
    }
}

fn sha2_256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
