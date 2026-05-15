use crate::connection::Connection;
use crate::mapper;
use crate::mapper::to_json_value_vec;
use oidc_core::OidcError;
use oidc_core::models::DeviceCode;
use uuid::Uuid;

/// PostgreSQL implementation of the DeviceCode repository.
pub struct DeviceCodeRepo;

/// Column list for device_codes SELECT queries (order must match map_row indices).
const DEVICE_CODE_COLUMNS: &str = r#"
    id, client_id, realm_id, device_code_hash, user_code,
    verification_uri, verification_uri_complete,
    expires_at, interval_seconds, used, authorized, user_id,
    scope, created_at
"#;

impl DeviceCodeRepo {
    /// Insert a new device code.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &DeviceCode,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO device_codes (
                id, client_id, realm_id, device_code_hash, user_code,
                verification_uri, verification_uri_complete,
                expires_at, interval_seconds, used, authorized, user_id,
                scope, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.client_id,
                &entity.realm_id,
                &entity.device_code,
                &entity.user_code,
                &entity.verification_uri,
                &entity.verification_uri_complete,
                &entity.expires_at,
                &entity.interval,
                &entity.used,
                &entity.authorized,
                &entity.user_id,
                &to_json_value_vec(&entity.scope),
                &entity.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find an active (unused, unexpired) device code by its hash.
    pub async fn find_by_device_code(
        &self,
        conn: &mut Connection,
        device_code_hash: &str,
    ) -> Result<Option<DeviceCode>, OidcError> {
        let sql = &format!(
            "SELECT {DEVICE_CODE_COLUMNS} FROM device_codes \
             WHERE device_code_hash = $1 AND NOT used AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&device_code_hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find an active (unexpired) device code by user_code.
    pub async fn find_by_user_code(
        &self,
        conn: &mut Connection,
        user_code: &str,
    ) -> Result<Option<DeviceCode>, OidcError> {
        let sql = &format!(
            "SELECT {DEVICE_CODE_COLUMNS} FROM device_codes \
             WHERE user_code = $1 AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&user_code])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Mark a device code as authorized with the given user.
    pub async fn mark_authorized(
        &self,
        conn: &mut Connection,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql =
            "UPDATE device_codes SET authorized = TRUE, user_id = $2 WHERE id = $1 AND NOT used";
        conn.execute_params(sql, &[&id, &user_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Mark a device code as used (exchanged for tokens).
    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE device_codes SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Delete expired device codes.
    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let sql = "DELETE FROM device_codes WHERE expires_at < NOW()";
        let affected = conn
            .execute_params(sql, &[])
            .await
            .map_err(mapper::pg_err)?;
        Ok(affected)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<DeviceCode, OidcError> {
        Ok(DeviceCode {
            id: mapper::uuid(row, 0)?,
            client_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            device_code: mapper::string(row, 3)?,
            user_code: mapper::string(row, 4)?,
            verification_uri: mapper::string(row, 5)?,
            verification_uri_complete: mapper::opt_string(row, 6)?,
            expires_at: mapper::datetime(row, 7)?,
            interval: mapper::i64_(row, 8)? as i32,
            used: mapper::bool_(row, 9)?,
            authorized: mapper::bool_(row, 10)?,
            user_id: mapper::opt_uuid(row, 11)?,
            scope: mapper::json_string_vec(row, 12)?,
            created_at: mapper::datetime(row, 13)?,
        })
    }
}
