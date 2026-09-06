use crate::{connection::Connection, mapper};
use oidc_core::{
    OidcError,
    models::{MfaCeremony, RecoveryCode, TotpCredential, WebauthnCredential},
};
use uuid::Uuid;

pub struct MfaRepo;

impl MfaRepo {
    pub async fn find_totp(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Option<TotpCredential>, OidcError> {
        let row = conn.query_one_params(
            "SELECT id,user_id,secret_encrypted,label,created_at,last_used_at FROM user_totp_credentials WHERE user_id=$1 FOR UPDATE",
            &[&user_id],
        ).await.map_err(mapper::pg_err)?;
        row.map(|r| {
            Ok(TotpCredential {
                id: mapper::uuid(&r, 0)?,
                user_id: mapper::uuid(&r, 1)?,
                secret_encrypted: mapper::string(&r, 2)?,
                label: mapper::string(&r, 3)?,
                created_at: mapper::datetime(&r, 4)?,
                last_used_at: mapper::opt_datetime(&r, 5)?,
            })
        })
        .transpose()
    }

    pub async fn save_totp(
        &self,
        conn: &mut Connection,
        value: &TotpCredential,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "INSERT INTO user_totp_credentials(id,user_id,secret_encrypted,label,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(user_id) DO UPDATE SET secret_encrypted=EXCLUDED.secret_encrypted,label=EXCLUDED.label,created_at=EXCLUDED.created_at,last_used_at=NULL",
            &[&value.id,&value.user_id,&value.secret_encrypted,&value.label,&value.created_at],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn touch_totp(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE user_totp_credentials SET last_used_at=NOW() WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_totp(&self, conn: &mut Connection, user_id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM user_totp_credentials WHERE user_id=$1",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_webauthn(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<WebauthnCredential>, OidcError> {
        let rows=conn.query_params("SELECT id,user_id,credential_id,credential,label,created_at,last_used_at FROM user_webauthn_credentials WHERE user_id=$1 ORDER BY created_at", &[&user_id]).await.map_err(mapper::pg_err)?;
        rows.into_rows()
            .iter()
            .map(|r| {
                Ok(WebauthnCredential {
                    id: mapper::uuid(r, 0)?,
                    user_id: mapper::uuid(r, 1)?,
                    credential_id: mapper::string(r, 2)?,
                    credential: r.get::<serde_json::Value>(3).map_err(mapper::pg_err)?,
                    label: mapper::string(r, 4)?,
                    created_at: mapper::datetime(r, 5)?,
                    last_used_at: mapper::opt_datetime(r, 6)?,
                })
            })
            .collect()
    }

    pub async fn save_webauthn(
        &self,
        conn: &mut Connection,
        value: &WebauthnCredential,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO user_webauthn_credentials(id,user_id,credential_id,credential,label,created_at) VALUES($1,$2,$3,$4,$5,$6)", &[&value.id,&value.user_id,&value.credential_id,&value.credential,&value.label,&value.created_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update_webauthn_counter(
        &self,
        conn: &mut Connection,
        id: Uuid,
        credential: &serde_json::Value,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE user_webauthn_credentials SET credential=$2,last_used_at=NOW() WHERE id=$1",
            &[&id, credential],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_webauthn(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        id: Uuid,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM user_webauthn_credentials WHERE id=$1 AND user_id=$2",
            &[&id, &user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn reset_user(&self, conn: &mut Connection, user_id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM user_totp_credentials WHERE user_id=$1",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        conn.execute_params(
            "DELETE FROM user_webauthn_credentials WHERE user_id=$1",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        conn.execute_params(
            "DELETE FROM user_recovery_codes WHERE user_id=$1",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        conn.execute_params("DELETE FROM mfa_ceremonies WHERE user_id=$1", &[&user_id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn replace_recovery_codes(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        codes: &[RecoveryCode],
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM user_recovery_codes WHERE user_id=$1",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        for code in codes {
            conn.execute_params(
                "INSERT INTO user_recovery_codes(id,user_id,code_hash) VALUES($1,$2,$3)",
                &[&code.id, &code.user_id, &code.code_hash],
            )
            .await
            .map_err(mapper::pg_err)?;
        }
        Ok(())
    }

    pub async fn available_recovery_codes(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<RecoveryCode>, OidcError> {
        let rows=conn.query_params("SELECT id,user_id,code_hash,used_at FROM user_recovery_codes WHERE user_id=$1 AND used_at IS NULL FOR UPDATE", &[&user_id]).await.map_err(mapper::pg_err)?;
        rows.into_rows()
            .iter()
            .map(|r| {
                Ok(RecoveryCode {
                    id: mapper::uuid(r, 0)?,
                    user_id: mapper::uuid(r, 1)?,
                    code_hash: mapper::string(r, 2)?,
                    used_at: mapper::opt_datetime(r, 3)?,
                })
            })
            .collect()
    }

    pub async fn use_recovery_code(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE user_recovery_codes SET used_at=NOW() WHERE id=$1 AND used_at IS NULL",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn recovery_code_count(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<i64, OidcError> {
        let row = conn
            .query_one_params(
                "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=$1 AND used_at IS NULL",
                &[&user_id],
            )
            .await
            .map_err(mapper::pg_err)?
            .ok_or_else(|| OidcError::Internal("recovery code count returned no row".into()))?;
        mapper::i64_(&row, 0)
    }

    pub async fn create_ceremony(
        &self,
        conn: &mut Connection,
        value: &MfaCeremony,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO mfa_ceremonies(id,token_hash,user_id,realm_id,client_id,purpose,state,attempts,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", &[&value.id,&value.token_hash,&value.user_id,&value.realm_id,&value.client_id,&value.purpose,&value.state,&value.attempts,&value.expires_at,&value.created_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn find_ceremony_for_update(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<MfaCeremony>, OidcError> {
        let row=conn.query_one_params("SELECT id,token_hash,user_id,realm_id,client_id,purpose,state,attempts,expires_at,used_at,created_at FROM mfa_ceremonies WHERE token_hash=$1 FOR UPDATE", &[&token_hash]).await.map_err(mapper::pg_err)?;
        row.map(|r| {
            Ok(MfaCeremony {
                id: mapper::uuid(&r, 0)?,
                token_hash: mapper::string(&r, 1)?,
                user_id: mapper::uuid(&r, 2)?,
                realm_id: mapper::uuid(&r, 3)?,
                client_id: mapper::opt_uuid(&r, 4)?,
                purpose: mapper::string(&r, 5)?,
                state: r.get::<serde_json::Value>(6).map_err(mapper::pg_err)?,
                attempts: r.get::<i32>(7).map_err(mapper::pg_err)?,
                expires_at: mapper::datetime(&r, 8)?,
                used_at: mapper::opt_datetime(&r, 9)?,
                created_at: mapper::datetime(&r, 10)?,
            })
        })
        .transpose()
    }

    pub async fn fail_ceremony(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE mfa_ceremonies SET attempts=attempts+1 WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn use_ceremony(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE mfa_ceremonies SET used_at=NOW() WHERE id=$1 AND used_at IS NULL",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }
}
