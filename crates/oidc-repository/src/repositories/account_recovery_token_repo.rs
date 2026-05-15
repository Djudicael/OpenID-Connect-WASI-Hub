use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::AccountRecoveryToken;
use uuid::Uuid;

/// PostgreSQL implementation of the AccountRecoveryToken repository.
pub struct AccountRecoveryTokenRepo;

/// Column list for account_recovery_tokens SELECT queries (order must match map_row indices).
const TOKEN_COLUMNS: &str = r#"
    id, user_id, realm_id, token_hash, expires_at, used, used_at, created_by, creator_ip, created_at
"#;

impl AccountRecoveryTokenRepo {
    /// Insert a new account recovery token.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &AccountRecoveryToken,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO account_recovery_tokens (id, user_id, realm_id, token_hash, expires_at, used, used_at, created_by, creator_ip, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.user_id,
                &entity.realm_id,
                &entity.token_hash,
                &entity.expires_at,
                &entity.used,
                &entity.used_at,
                &entity.created_by,
                &entity.creator_ip,
                &entity.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find an active (unused, unexpired) recovery token by its hash.
    pub async fn find_by_token_hash(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<AccountRecoveryToken>, OidcError> {
        let sql = &format!(
            "SELECT {TOKEN_COLUMNS} FROM account_recovery_tokens WHERE token_hash = $1 AND NOT used AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&token_hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Mark a recovery token as used.
    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE account_recovery_tokens SET used = TRUE, used_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find all recovery tokens for a given user.
    pub async fn find_by_user_id(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<AccountRecoveryToken>, OidcError> {
        let sql = &format!(
            "SELECT {TOKEN_COLUMNS} FROM account_recovery_tokens WHERE user_id = $1 ORDER BY created_at DESC"
        );
        let result = conn
            .query_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|r| Self::map_row(r))
            .collect()
    }

    /// Delete expired (and unused) recovery tokens. Returns the number of deleted rows.
    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let sql = "DELETE FROM account_recovery_tokens WHERE expires_at <= NOW() AND NOT used";
        let affected = conn
            .execute_params(sql, &[])
            .await
            .map_err(mapper::pg_err)?;
        Ok(affected)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<AccountRecoveryToken, OidcError> {
        Ok(AccountRecoveryToken {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            token_hash: mapper::string(row, 3)?,
            expires_at: mapper::datetime(row, 4)?,
            used: mapper::bool_(row, 5)?,
            used_at: mapper::opt_datetime(row, 6)?,
            created_by: mapper::uuid(row, 7)?,
            creator_ip: mapper::opt_string(row, 8)?,
            created_at: mapper::datetime(row, 9)?,
        })
    }
}
