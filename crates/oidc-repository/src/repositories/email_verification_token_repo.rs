use crate::connection::Connection;
use crate::mapper;
use oidc_core::OidcError;
use oidc_core::models::EmailVerificationToken;
use uuid::Uuid;

pub struct EmailVerificationTokenRepo;

const TOKEN_COLUMNS: &str = r#"
    id, user_id, realm_id, email, token_hash, used, expires_at, created_at
"#;

impl EmailVerificationTokenRepo {
    pub async fn create(
        &self,
        conn: &mut Connection,
        entity: &EmailVerificationToken,
    ) -> Result<(), OidcError> {
        let sql = r#"
            INSERT INTO email_verification_tokens (id, user_id, realm_id, email, token_hash, used, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#;
        conn.execute_params(
            sql,
            &[
                &entity.id,
                &entity.user_id,
                &entity.realm_id,
                &entity.email,
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

    pub async fn find_by_token_hash(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationToken>, OidcError> {
        let sql = &format!(
            "SELECT {TOKEN_COLUMNS} FROM email_verification_tokens WHERE token_hash = $1 AND NOT used AND expires_at > NOW()"
        );
        let row = conn
            .query_one_params(sql, &[&token_hash])
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| Self::map_row(&r)).transpose()
    }

    pub async fn mark_used(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let sql = "UPDATE email_verification_tokens SET used = TRUE WHERE id = $1";
        conn.execute_params(sql, &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_row(row: &wasi_pg_client::Row) -> Result<EmailVerificationToken, OidcError> {
        Ok(EmailVerificationToken {
            id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            realm_id: mapper::uuid(row, 2)?,
            email: mapper::string(row, 3)?,
            token_hash: mapper::string(row, 4)?,
            used: mapper::bool_(row, 5)?,
            expires_at: mapper::datetime(row, 6)?,
            created_at: mapper::datetime(row, 7)?,
        })
    }
}
