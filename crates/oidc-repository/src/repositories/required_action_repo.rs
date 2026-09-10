use crate::{Connection, mapper};
use oidc_core::{
    OidcError,
    models::{RequiredActionKind, RequiredActionSession},
};
use uuid::Uuid;

pub struct RequiredActionRepo;

impl RequiredActionRepo {
    pub async fn list(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<RequiredActionKind>, OidcError> {
        let rows = conn
            .query_params(
                "SELECT action FROM user_required_actions WHERE user_id=$1 ORDER BY created_at",
                &[&user_id],
            )
            .await
            .map_err(mapper::pg_err)?;
        Ok(rows
            .into_rows()
            .iter()
            .filter_map(|r| mapper::string(r, 0).ok()?.parse().ok())
            .collect())
    }
    pub async fn replace(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        actions: &[RequiredActionKind],
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM user_required_actions WHERE user_id=$1",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        for action in actions {
            conn.execute_params("INSERT INTO user_required_actions(user_id,action) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&user_id,&action.as_str()]).await.map_err(mapper::pg_err)?;
        }
        Ok(())
    }
    pub async fn complete(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        action: RequiredActionKind,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "DELETE FROM user_required_actions WHERE user_id=$1 AND action=$2",
            &[&user_id, &action.as_str()],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn has_accepted_terms(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        version: &str,
    ) -> Result<bool, OidcError> {
        Ok(conn
            .query_one_params(
                "SELECT 1 FROM user_terms_acceptances WHERE user_id=$1 AND version=$2",
                &[&user_id, &version],
            )
            .await
            .map_err(mapper::pg_err)?
            .is_some())
    }
    pub async fn accept_terms(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
        version: &str,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO user_terms_acceptances(user_id,version) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&user_id,&version]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn create_session(
        &self,
        conn: &mut Connection,
        v: &RequiredActionSession,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO required_action_sessions(id,token_hash,user_id,realm_id,client_id,expires_at) VALUES($1,$2,$3,$4,$5,$6)", &[&v.id,&v.token_hash,&v.user_id,&v.realm_id,&v.client_id,&v.expires_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn find_session(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<RequiredActionSession>, OidcError> {
        let row = conn.query_one_params("SELECT id,token_hash,user_id,realm_id,client_id,expires_at,used_at FROM required_action_sessions WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW()", &[&token_hash]).await.map_err(mapper::pg_err)?;
        row.map(|r| {
            Ok(RequiredActionSession {
                id: mapper::uuid(&r, 0)?,
                token_hash: mapper::string(&r, 1)?,
                user_id: mapper::uuid(&r, 2)?,
                realm_id: mapper::uuid(&r, 3)?,
                client_id: mapper::uuid(&r, 4)?,
                expires_at: mapper::datetime(&r, 5)?,
                used_at: mapper::opt_datetime(&r, 6)?,
            })
        })
        .transpose()
    }
    pub async fn use_session(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE required_action_sessions SET used_at=NOW() WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }
}
