use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::signing_key::{Algorithm, SigningKey};
use uuid::Uuid;

/// PostgreSQL implementation of the SigningKey repository.
pub struct SigningKeyRepo;

impl SigningKeyRepo {
    /// Find a signing key by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<SigningKey>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, kid, algorithm, public_key_pem,
                   private_key_pem_encrypted, active, created_at, expires_at, retired_at
            FROM signing_keys
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a signing key by its Key ID (kid).
    pub async fn find_by_kid(
        &self,
        conn: &mut Connection,
        kid: &str,
    ) -> Result<Option<SigningKey>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, kid, algorithm, public_key_pem,
                   private_key_pem_encrypted, active, created_at, expires_at, retired_at
            FROM signing_keys
            WHERE kid = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&kid])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all active signing keys for a realm.
    pub async fn find_active_by_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<SigningKey>, OidcError> {
        let sql = r#"
            SELECT id, realm_id, kid, algorithm, public_key_pem,
                   private_key_pem_encrypted, active, created_at, expires_at, retired_at
            FROM signing_keys
            WHERE realm_id = $1 AND active = TRUE
        "#;
        let result = conn
            .query_params(sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Insert a new signing key.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &SigningKey,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO signing_keys (
                id, realm_id, kid, algorithm, public_key_pem,
                private_key_pem_encrypted, active, created_at, expires_at, retired_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.realm_id,
                &entity.kid,
                &entity.algorithm.to_string(),
                &entity.public_key_pem,
                &entity.private_key_pem_encrypted,
                &entity.active,
                &entity.created_at,
                &entity.expires_at,
                &entity.retired_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update an existing signing key.
    pub async fn update(
        &self,
        conn: &mut Connection,
        entity: &SigningKey,
    ) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE signing_keys SET
                kid = $1,
                algorithm = $2,
                public_key_pem = $3,
                private_key_pem_encrypted = $4,
                active = $5,
                expires_at = $6,
                retired_at = $7
            WHERE id = $8
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.kid,
                &entity.algorithm.to_string(),
                &entity.public_key_pem,
                &entity.private_key_pem_encrypted,
                &entity.active,
                &entity.expires_at,
                &entity.retired_at,
                &entity.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Retire a signing key (sets active = FALSE and retired_at = NOW()).
    pub async fn retire(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE signing_keys
            SET active = FALSE, retired_at = NOW()
            WHERE id = $1
        "#;
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<SigningKey, OidcError> {
        let algo_str: String = mapper::string(row, 3)?;
        let algorithm = match algo_str.as_str() {
            "RS256" => Algorithm::Rs256,
            _ => Algorithm::EdDSA,
        };
        Ok(SigningKey {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            kid: mapper::string(row, 2)?,
            algorithm,
            public_key_pem: mapper::string(row, 4)?,
            private_key_pem_encrypted: mapper::opt_string(row, 5)?,
            active: mapper::bool_(row, 6)?,
            created_at: mapper::datetime(row, 7)?,
            expires_at: mapper::opt_datetime(row, 8)?,
            retired_at: mapper::opt_datetime(row, 9)?,
        })
    }
}
