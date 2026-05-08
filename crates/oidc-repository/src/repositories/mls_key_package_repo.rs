use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::mls::KeyPackageEntry;
use uuid::Uuid;

/// PostgreSQL implementation of the MLS KeyPackage repository.
pub struct MlsKeyPackageRepo;

impl MlsKeyPackageRepo {
    /// Find a KeyPackage by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<KeyPackageEntry>, OidcError> {
        let sql = r#"
            SELECT id, user_id, key_package_ref, key_package_encrypted, used, created_at, expires_at
            FROM mls_key_packages
            WHERE id = $1
        "#;
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a KeyPackage by its reference hash.
    pub async fn find_by_ref(
        &self,
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
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find all unused KeyPackages for a user.
    pub async fn find_unused_by_user(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<KeyPackageEntry>, OidcError> {
        let sql = r#"
            SELECT id, user_id, key_package_ref, key_package_encrypted, used, created_at, expires_at
            FROM mls_key_packages
            WHERE user_id = $1 AND NOT used
        "#;
        let result = conn
            .query_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Insert a new KeyPackage.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &KeyPackageEntry,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO mls_key_packages (
                id, user_id, key_package_ref, key_package_encrypted, used, created_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.user_id,
                &entity.key_package_ref,
                &entity.key_package_encrypted,
                &entity.used,
                &entity.created_at,
                &entity.expires_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Mark a KeyPackage as used.
    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE mls_key_packages SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Delete a KeyPackage by ID.
    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "DELETE FROM mls_key_packages WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<KeyPackageEntry, OidcError> {
        Ok(KeyPackageEntry {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            key_package_ref: mapper::bytes(row, 2)?,
            key_package_encrypted: mapper::bytes(row, 3)?,
            used: mapper::bool_(row, 4)?,
            created_at: mapper::datetime(row, 5)?,
            expires_at: mapper::opt_datetime(row, 6)?,
        })
    }
}
