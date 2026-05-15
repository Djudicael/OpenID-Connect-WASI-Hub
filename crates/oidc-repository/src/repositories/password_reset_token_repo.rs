use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::PasswordResetToken;
use uuid::Uuid;

/// PostgreSQL implementation of the PasswordResetToken repository.
pub struct PasswordResetTokenRepo;

/// Column list for password_reset_token SELECT queries (order must match map_row indices).
const TOKEN_COLUMNS: &str = r#"
    id, user_id, realm_id, token_hash, used, expires_at, created_at
"#;

impl PasswordResetTokenRepo {
    /// Insert a new password reset token.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &PasswordResetToken,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO password_reset_tokens (id, user_id, realm_id, token_hash, used, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.user_id,
                &entity.realm_id,
                &entity.token_hash,
                &entity.used,
                &entity.expires_at,
                &entity.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find an active (unused, unexpired) reset token by its hash.
    pub async fn find_by_token_hash(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<PasswordResetToken>, OidcError> {
        let sql = &format!(
            "SELECT {TOKEN_COLUMNS} FROM password_reset_tokens WHERE token_hash = $1 AND NOT used AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&token_hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Mark a reset token as used.
    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE password_reset_tokens SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<PasswordResetToken, OidcError> {
        Ok(PasswordResetToken {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            token_hash: mapper::string(row, 3)?,
            used: mapper::bool_(row, 4)?,
            expires_at: mapper::datetime(row, 5)?,
            created_at: mapper::datetime(row, 6)?,
        })
    }
}
