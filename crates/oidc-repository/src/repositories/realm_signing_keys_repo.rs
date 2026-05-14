use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::RealmSigningKeys;
use uuid::Uuid;

/// PostgreSQL implementation of the RealmSigningKeys repository.
pub struct RealmSigningKeysRepo;

impl RealmSigningKeysRepo {
    /// Find signing keys for a realm by its ID.
    pub async fn find_by_realm_id(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Option<RealmSigningKeys>, OidcError> {
        let sql = r#"
            SELECT realm_id, rsa_private_pem, rsa_kid, rsa_public_n, rsa_public_e,
                   ed25519_private_pem, ed25519_kid, ed25519_public_x, created_at, updated_at
            FROM realm_signing_keys
            WHERE realm_id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert new realm signing keys.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &RealmSigningKeys,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO realm_signing_keys (
                realm_id, rsa_private_pem, rsa_kid, rsa_public_n, rsa_public_e,
                ed25519_private_pem, ed25519_kid, ed25519_public_x, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.realm_id,
                &entity.rsa_private_pem,
                &entity.rsa_kid,
                &entity.rsa_public_n,
                &entity.rsa_public_e,
                &entity.ed25519_private_pem,
                &entity.ed25519_kid,
                &entity.ed25519_public_x,
                &entity.created_at,
                &entity.updated_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Update existing realm signing keys.
    pub async fn update(
        &self,
        conn: &mut Connection,
        entity: &RealmSigningKeys,
    ) -> Result<(), OidcError> {
        let sql = r#"
            UPDATE realm_signing_keys SET
                rsa_private_pem = $1,
                rsa_kid = $2,
                rsa_public_n = $3,
                rsa_public_e = $4,
                ed25519_private_pem = $5,
                ed25519_kid = $6,
                ed25519_public_x = $7,
                updated_at = $8
            WHERE realm_id = $9
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.rsa_private_pem,
                &entity.rsa_kid,
                &entity.rsa_public_n,
                &entity.rsa_public_e,
                &entity.ed25519_private_pem,
                &entity.ed25519_kid,
                &entity.ed25519_public_x,
                &entity.updated_at,
                &entity.realm_id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Delete signing keys for a realm.
    pub async fn delete_by_realm_id(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = "DELETE FROM realm_signing_keys WHERE realm_id = $1";
        conn.execute_params(sql, &[&realm_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<RealmSigningKeys, OidcError> {
        Ok(RealmSigningKeys {
            realm_id: mapper::uuid(row, 0)?,
            rsa_private_pem: mapper::string(row, 1)?,
            rsa_kid: mapper::string(row, 2)?,
            rsa_public_n: mapper::string(row, 3)?,
            rsa_public_e: mapper::string(row, 4)?,
            ed25519_private_pem: mapper::string(row, 5)?,
            ed25519_kid: mapper::string(row, 6)?,
            ed25519_public_x: mapper::string(row, 7)?,
            created_at: mapper::datetime(row, 8)?,
            updated_at: mapper::datetime(row, 9)?,
        })
    }
}
