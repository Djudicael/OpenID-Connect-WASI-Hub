use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::Session;
use uuid::Uuid;

/// PostgreSQL implementation of the Session repository.
pub struct SessionRepo;

/// Column list for session SELECT queries (order must match map_row indices).
const SESSION_COLUMNS: &str = r#"
    id, sid, user_id, realm_id, client_id, grant_type,
    access_token_hash, refresh_token_hash, id_token_jti,
    scope, revoked, expires_at, refresh_expires_at,
    created_at, last_used_at,
    token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
"#;

impl SessionRepo {
    /// Find a session by its primary key.
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Session>, OidcError> {
        let sql = &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE id = $1");
        let row = conn
            .query_one_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a non-revoked, non-expired session by access token hash.
    pub async fn find_by_access_token_hash(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = &format!(
            "SELECT {SESSION_COLUMNS} FROM sessions WHERE access_token_hash = $1 AND NOT revoked AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new session.
    pub async fn create(&self, conn: &mut Connection, entity: &Session) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO sessions (
                id, sid, user_id, realm_id, client_id, grant_type,
                access_token_hash, refresh_token_hash, id_token_jti,
                scope, revoked, expires_at, refresh_expires_at,
                token_family_id, previous_session_id, rotated_at, reused_at, family_revoked
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.sid,
                &entity.user_id,
                &entity.realm_id,
                &entity.client_id,
                &entity.grant_type,
                &entity.access_token_hash,
                &entity.refresh_token_hash,
                &entity.id_token_jti,
                &mapper::to_json_value_vec(&entity.scope),
                &entity.revoked,
                &entity.expires_at,
                &entity.refresh_expires_at,
                &entity.token_family_id,
                &entity.previous_session_id,
                &entity.rotated_at,
                &entity.reused_at,
                &entity.family_revoked,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find a non-revoked session by refresh token hash.
    pub async fn find_by_refresh_token_hash(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = &format!(
            "SELECT {SESSION_COLUMNS} FROM sessions WHERE refresh_token_hash = $1 AND NOT revoked FOR UPDATE"
        );
        let row = conn
            .query_one_params(sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Find a non-revoked, non-expired session by refresh token hash.
    pub async fn find_active_by_refresh_token_hash(
        &self,
        conn: &mut Connection,
        hash: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = &format!(
            "SELECT {SESSION_COLUMNS} FROM sessions WHERE refresh_token_hash = $1 AND NOT revoked AND refresh_expires_at > NOW() FOR UPDATE"
        );
        let row = conn
            .query_one_params(sql, &[&hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Revoke a session by ID.
    pub async fn revoke(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE sessions SET revoked = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Mark a session as reused (token theft detection).
    pub async fn mark_reused(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE sessions SET reused_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Revoke all active sessions for a user.
    pub async fn revoke_by_user_id(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql = "UPDATE sessions SET revoked = TRUE WHERE user_id = $1 AND NOT revoked";
        conn.execute_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Find all active (non-revoked, non-expired) sessions for a user.
    /// Used for front-channel and back-channel logout notifications.
    pub async fn find_active_by_user_id(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<Session>, OidcError> {
        let sql = &format!(
            "SELECT {SESSION_COLUMNS} FROM sessions WHERE user_id = $1 AND NOT revoked AND expires_at > NOW()"
        );
        let result = conn
            .query_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|row| Self::map_row(row))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Find a session by its OIDC Session ID (`sid`).
    pub async fn find_by_sid(
        &self,
        conn: &mut Connection,
        sid: &str,
    ) -> Result<Option<Session>, OidcError> {
        let sql = &format!("SELECT {SESSION_COLUMNS} FROM sessions WHERE sid = $1");
        let row = conn
            .query_one_params(sql, &[&sid])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Mark a session as rotated (sets rotated_at to NOW()).
    pub async fn mark_rotated(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE sessions SET rotated_at = NOW() WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// Revoke all sessions in a token family.
    pub async fn revoke_family(
        &self,
        conn: &mut Connection,
        family_id: Uuid,
    ) -> Result<(), OidcError> {
        let sql =
            "UPDATE sessions SET revoked = TRUE, family_revoked = TRUE WHERE token_family_id = $1";
        conn.execute_params(sql, &[&family_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    /// List sessions with optional filters and pagination.
    /// Builds the WHERE clause dynamically to avoid combinatorial explosion.
    pub async fn list(
        &self,
        conn: &mut Connection,
        user_id: Option<Uuid>,
        realm_id: Option<Uuid>,
        revoked: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>, OidcError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx = 1usize;

        if user_id.is_some() {
            where_clauses.push(format!("user_id = ${}", param_idx));
            param_idx += 1;
        }
        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${}", param_idx));
            param_idx += 1;
        }
        if revoked.is_some() {
            where_clauses.push(format!("revoked = ${}", param_idx));
            param_idx += 1;
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let limit_idx = param_idx;
        let offset_idx = param_idx + 1;

        let sql = format!(
            "SELECT {SESSION_COLUMNS} FROM sessions {where_sql} ORDER BY created_at DESC LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        // Build params in order
        let user_id_ref = user_id.as_ref();
        let realm_id_ref = realm_id.as_ref();
        let revoked_ref = revoked.as_ref();

        let mut params: Vec<&dyn wasi_pg_client::pg_types::ToSql> = Vec::new();
        if let Some(uid) = user_id_ref {
            params.push(uid);
        }
        if let Some(rid) = realm_id_ref {
            params.push(rid);
        }
        if let Some(r) = revoked_ref {
            params.push(r);
        }
        params.push(&limit);
        params.push(&offset);

        let result = conn
            .query_params(&sql, &params)
            .await
            .map_err(mapper::pg_err)?;
        result
            .into_rows()
            .iter()
            .map(|row| Self::map_row(row))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Count sessions with optional filters.
    /// Builds the WHERE clause dynamically to avoid combinatorial explosion.
    pub async fn count(
        &self,
        conn: &mut Connection,
        user_id: Option<Uuid>,
        realm_id: Option<Uuid>,
        revoked: Option<bool>,
    ) -> Result<i64, OidcError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut param_idx = 1usize;

        if user_id.is_some() {
            where_clauses.push(format!("user_id = ${}", param_idx));
            param_idx += 1;
        }
        if realm_id.is_some() {
            where_clauses.push(format!("realm_id = ${}", param_idx));
            param_idx += 1;
        }
        if revoked.is_some() {
            where_clauses.push(format!("revoked = ${}", param_idx));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let sql = format!("SELECT COUNT(*) FROM sessions {where_sql}");

        let user_id_ref = user_id.as_ref();
        let realm_id_ref = realm_id.as_ref();
        let revoked_ref = revoked.as_ref();

        let mut params: Vec<&dyn wasi_pg_client::pg_types::ToSql> = Vec::new();
        if let Some(uid) = user_id_ref {
            params.push(uid);
        }
        if let Some(rid) = realm_id_ref {
            params.push(rid);
        }
        if let Some(r) = revoked_ref {
            params.push(r);
        }

        let result = if params.is_empty() {
            conn.query(&sql).await.map_err(mapper::pg_err)?
        } else {
            conn.query_params(&sql, &params)
                .await
                .map_err(mapper::pg_err)?
        };
        let row = result
            .into_rows()
            .into_iter()
            .next()
            .ok_or(OidcError::Internal("count returned no rows".into()))?;
        mapper::i64_(&row, 0)
    }

    /// Delete expired sessions.
    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let sql = "DELETE FROM sessions WHERE expires_at < NOW()";
        let affected = conn
            .execute_params(sql, &[])
            .await
            .map_err(mapper::pg_err)?;
        Ok(affected)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<Session, OidcError> {
        Ok(Session {
            id: mapper::uuid(row, 0)?,
            sid: mapper::string(row, 1)?,
            user_id: mapper::opt_uuid(row, 2)?,
            realm_id: mapper::uuid(row, 3)?,
            client_id: mapper::uuid(row, 4)?,
            grant_type: mapper::string(row, 5)?,
            access_token_hash: mapper::string(row, 6)?,
            refresh_token_hash: mapper::opt_string(row, 7)?,
            id_token_jti: mapper::opt_string(row, 8)?,
            scope: mapper::json_string_vec(row, 9)?,
            revoked: mapper::bool_(row, 10)?,
            expires_at: mapper::datetime(row, 11)?,
            refresh_expires_at: mapper::opt_datetime(row, 12)?,
            created_at: mapper::datetime(row, 13)?,
            last_used_at: mapper::opt_datetime(row, 14)?,
            token_family_id: mapper::opt_uuid(row, 15)?,
            previous_session_id: mapper::opt_uuid(row, 16)?,
            rotated_at: mapper::opt_datetime(row, 17)?,
            reused_at: mapper::opt_datetime(row, 18)?,
            family_revoked: mapper::bool_(row, 19)?,
        })
    }
}
