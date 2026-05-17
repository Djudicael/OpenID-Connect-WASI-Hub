use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::SocialLoginState;
use uuid::Uuid;

/// PostgreSQL implementation of the persisted social-login state repository.
pub struct SocialLoginStateRepo;

const SOCIAL_LOGIN_STATE_COLUMNS: &str = r#"
    id, state_token_hash, realm_id, identity_provider_id, client_id,
    redirect_uri, original_state, nonce, expires_at, used, created_at
"#;

impl SocialLoginStateRepo {
    /// Insert a new social-login state entry.
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &SocialLoginState,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO social_login_states (
                id, state_token_hash, realm_id, identity_provider_id, client_id,
                redirect_uri, original_state, nonce, expires_at, used, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.state_token_hash,
                &entity.realm_id,
                &entity.identity_provider_id,
                &entity.client_id,
                &entity.redirect_uri,
                &entity.original_state,
                &entity.nonce,
                &entity.expires_at,
                &entity.used,
                &entity.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Atomically consume a valid social-login state.
    ///
    /// The row is returned only if it matches the expected realm/provider,
    /// has not expired, and has not already been used.
    pub async fn consume_valid(
        &self,
        conn: &mut Connection,
        state_token_hash: &str,
        realm_id: Uuid,
        identity_provider_id: Uuid,
    ) -> Result<Option<SocialLoginState>, OidcError> {
        let sql = &format!(
            r#"
            UPDATE social_login_states
            SET used = TRUE
            WHERE id = (
                SELECT id
                FROM social_login_states
                WHERE state_token_hash = $1
                  AND realm_id = $2
                  AND identity_provider_id = $3
                  AND NOT used
                  AND expires_at > NOW()
                LIMIT 1
            )
            RETURNING {SOCIAL_LOGIN_STATE_COLUMNS}
            "#
        );
        let row = conn
            .query_one_params(sql, &[&state_token_hash, &realm_id, &identity_provider_id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Delete expired or already-consumed state rows.
    pub async fn cleanup_stale(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let sql = "DELETE FROM social_login_states WHERE used = TRUE OR expires_at <= NOW()";
        conn.execute_params(sql, &[]).await.map_err(mapper::pg_err)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<SocialLoginState, OidcError> {
        Ok(SocialLoginState {
            id: mapper::uuid(row, 0)?,
            state_token_hash: mapper::string(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            identity_provider_id: mapper::uuid(row, 3)?,
            client_id: mapper::uuid(row, 4)?,
            redirect_uri: mapper::string(row, 5)?,
            original_state: mapper::opt_string(row, 6)?,
            nonce: mapper::opt_string(row, 7)?,
            expires_at: mapper::datetime(row, 8)?,
            used: mapper::bool_(row, 9)?,
            created_at: mapper::datetime(row, 10)?,
        })
    }
}
