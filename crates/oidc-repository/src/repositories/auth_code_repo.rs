use crate::connection::Connection;
use crate::mapper;
use oidc_core::models::AuthCode;
use oidc_core::OidcError;
use uuid::Uuid;

/// PostgreSQL implementation of the AuthCode repository.
pub struct AuthCodeRepo;

impl AuthCodeRepo {
    /// Find an active (unused, unexpired) authorization code by its code string.
    pub async fn find_by_code(
        &self,
        conn: &mut Connection,
        code: &str,
    ) -> Result<Option<AuthCode>, OidcError> {
        let sql = r#"
            SELECT id, code, client_id, user_id, realm_id, redirect_uri,
                   scope, code_challenge, code_challenge_method, used, expires_at
            FROM authorization_codes
            WHERE code = $1 AND NOT used AND expires_at > NOW()
        "#;
        let row = conn
            .query_one_params(sql, &[&code])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new authorization code.
    pub async fn create(&self, conn: &mut Connection, entity: &AuthCode) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO authorization_codes (
                id, code, client_id, user_id, realm_id, redirect_uri,
                scope, code_challenge, code_challenge_method, used, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11))
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.code,
                &entity.client_id,
                &entity.user_id,
                &entity.realm_id,
                &entity.redirect_uri,
                &mapper::to_json_value_vec(&entity.scope),
                &entity.code_challenge,
                &entity.code_challenge_method,
                &entity.used,
                &entity.expires_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Mark an authorization code as used.
    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE authorization_codes SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<AuthCode, OidcError> {
        Ok(AuthCode {
            id: mapper::uuid(row, 0)?,
            code: mapper::string(row, 1)?,
            client_id: mapper::uuid(row, 2)?,
            user_id: mapper::uuid(row, 3)?,
            realm_id: mapper::uuid(row, 4)?,
            redirect_uri: mapper::string(row, 5)?,
            scope: mapper::json_string_vec(row, 6)?,
            code_challenge: mapper::string(row, 7)?,
            code_challenge_method: mapper::string(row, 8)?,
            used: mapper::bool_(row, 9)?,
            expires_at: mapper::i64_(row, 10)?,
        })
    }
}
