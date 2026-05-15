use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::AuthCode;
use oidc_core::models::auth_code::CodeChallengeMethod;
use std::str::FromStr;
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
        let code_hash = oidc_core::utils::sha2_256_hex(code);
        let sql = r#"
            SELECT id, code, client_id, user_id, realm_id, redirect_uri,
                               scope, code_challenge, code_challenge_method, nonce, used, claims_request, display, response_type, acr_values, claims_locales, expires_at, response_mode, authorization_details, resource
            FROM authorization_codes
            WHERE code = $1 AND NOT used AND expires_at > NOW() FOR UPDATE
        "#;
        let row = conn
            .query_one_params(sql, &[&code_hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    /// Insert a new authorization code.
    pub async fn create(&self, conn: &mut Connection, entity: &AuthCode) -> Result<(), OidcError> {
        let code_hash = oidc_core::utils::sha2_256_hex(&entity.code);
        let sql = r#"
            INSERT INTO authorization_codes (
                            id, code, client_id, user_id, realm_id, redirect_uri,
                            scope, code_challenge, code_challenge_method, nonce, used, claims_request, display, response_type, acr_values, claims_locales, expires_at, response_mode, authorization_details, resource
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &code_hash,
                &entity.client_id,
                &entity.user_id,
                &entity.realm_id,
                &entity.redirect_uri,
                &mapper::to_json_value_vec(&entity.scope),
                &entity.code_challenge,
                &entity.code_challenge_method.to_string(),
                &entity.nonce,
                &entity.used,
                &entity.claims_request,
                &entity.display,
                &entity.response_type.to_string(),
                &mapper::to_json_value_vec(&entity.acr_values),
                &mapper::to_json_value_vec(&entity.claims_locales),
                &entity.expires_at,
                &entity.response_mode,
                &entity.authorization_details,
                &mapper::to_json_value_vec(&entity.resource),
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

    /// Delete expired authorization codes.
    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let sql = "DELETE FROM authorization_codes WHERE expires_at < NOW()";
        let affected = conn
            .execute_params(sql, &[])
            .await
            .map_err(mapper::pg_err)?;
        Ok(affected)
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<AuthCode, OidcError> {
        let method_str: String = mapper::string(row, 8)?;
        let code_challenge_method = CodeChallengeMethod::from_str(&method_str).map_err(|_| {
            OidcError::Internal(format!("Invalid code_challenge_method: {}", method_str))
        })?;

        Ok(AuthCode {
            id: mapper::uuid(row, 0)?,
            code: mapper::string(row, 1)?,
            client_id: mapper::uuid(row, 2)?,
            user_id: mapper::uuid(row, 3)?,
            realm_id: mapper::uuid(row, 4)?,
            redirect_uri: mapper::string(row, 5)?,
            scope: mapper::json_string_vec(row, 6)?,
            code_challenge: mapper::string(row, 7)?,
            code_challenge_method,
            nonce: mapper::opt_string(row, 9)?,
            used: mapper::bool_(row, 10)?,
            claims_request: row.get::<serde_json::Value>(11).ok(),
            display: mapper::opt_string(row, 12)?,
            response_type: {
                let rt_str: String = mapper::string(row, 13)?;
                oidc_core::models::ResponseType::parse(&rt_str).map_err(|_| {
                    OidcError::Internal(format!("Invalid response_type: {}", rt_str))
                })?
            },
            acr_values: mapper::json_string_vec(row, 14)?,
            claims_locales: mapper::json_string_vec(row, 15)?,
            expires_at: mapper::datetime(row, 16)?,
            response_mode: mapper::opt_string(row, 17)?,
            authorization_details: row.get::<serde_json::Value>(18).ok(),
            resource: mapper::json_string_vec(row, 19)?,
        })
    }
}
