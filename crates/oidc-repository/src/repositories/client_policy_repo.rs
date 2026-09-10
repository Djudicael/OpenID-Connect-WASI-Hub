use oidc_core::{
    OidcError,
    models::{ClientPolicy, ClientPolicyCondition, ClientPolicyExecutor, ClientPolicyProfile},
};
use uuid::Uuid;

use crate::{Connection, mapper};

pub struct ClientPolicyRepo;

impl ClientPolicyRepo {
    pub async fn list_profiles(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<ClientPolicyProfile>, OidcError> {
        let rows=conn.query_params("SELECT id,realm_id,name,description,executors,created_at,updated_at FROM client_policy_profiles WHERE realm_id=$1 ORDER BY lower(name)",&[&realm_id]).await.map_err(mapper::pg_err)?;
        rows.iter().map(Self::map_profile).collect()
    }
    pub async fn find_profile(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<ClientPolicyProfile>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,name,description,executors,created_at,updated_at FROM client_policy_profiles WHERE id=$1",&[&id]).await.map_err(mapper::pg_err)?.map(|r|Self::map_profile(&r)).transpose()
    }
    pub async fn create_profile(
        &self,
        conn: &mut Connection,
        v: &ClientPolicyProfile,
    ) -> Result<(), OidcError> {
        let executors = serde_json::to_value(&v.executors)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        conn.execute_params("INSERT INTO client_policy_profiles(id,realm_id,name,description,executors,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&v.id,&v.realm_id,&v.name,&v.description,&executors,&v.created_at,&v.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn update_profile(
        &self,
        conn: &mut Connection,
        v: &ClientPolicyProfile,
    ) -> Result<(), OidcError> {
        let executors = serde_json::to_value(&v.executors)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        conn.execute_params("UPDATE client_policy_profiles SET name=$2,description=$3,executors=$4,updated_at=$5 WHERE id=$1",&[&v.id,&v.name,&v.description,&executors,&v.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn delete_profile(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        let count = conn
            .query_one_params(
                "SELECT COUNT(*) FROM client_policies WHERE profile_ids ? $1",
                &[&id.to_string()],
            )
            .await
            .map_err(mapper::pg_err)?
            .ok_or_else(|| OidcError::Internal("profile reference check returned no row".into()))?
            .get::<i64>(0)
            .map_err(mapper::pg_err)?;
        if count > 0 {
            return Err(OidcError::Conflict(
                "profile is assigned to a client policy".into(),
            ));
        }
        conn.execute_params("DELETE FROM client_policy_profiles WHERE id=$1", &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn list_policies(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<Vec<ClientPolicy>, OidcError> {
        let rows=conn.query_params("SELECT id,realm_id,name,description,enabled,priority,conditions,profile_ids,created_at,updated_at FROM client_policies WHERE realm_id=$1 ORDER BY priority,lower(name)",&[&realm_id]).await.map_err(mapper::pg_err)?;
        rows.iter().map(Self::map_policy).collect()
    }
    pub async fn find_policy(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<ClientPolicy>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,name,description,enabled,priority,conditions,profile_ids,created_at,updated_at FROM client_policies WHERE id=$1",&[&id]).await.map_err(mapper::pg_err)?.map(|r|Self::map_policy(&r)).transpose()
    }
    pub async fn create_policy(
        &self,
        conn: &mut Connection,
        v: &ClientPolicy,
    ) -> Result<(), OidcError> {
        let conditions = serde_json::to_value(&v.conditions)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        let profiles = serde_json::to_value(&v.profile_ids)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        conn.execute_params("INSERT INTO client_policies(id,realm_id,name,description,enabled,priority,conditions,profile_ids,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",&[&v.id,&v.realm_id,&v.name,&v.description,&v.enabled,&v.priority,&conditions,&profiles,&v.created_at,&v.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn update_policy(
        &self,
        conn: &mut Connection,
        v: &ClientPolicy,
    ) -> Result<(), OidcError> {
        let conditions = serde_json::to_value(&v.conditions)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        let profiles = serde_json::to_value(&v.profile_ids)
            .map_err(|e| OidcError::InvalidInput(e.to_string()))?;
        conn.execute_params("UPDATE client_policies SET name=$2,description=$3,enabled=$4,priority=$5,conditions=$6,profile_ids=$7,updated_at=$8 WHERE id=$1",&[&v.id,&v.name,&v.description,&v.enabled,&v.priority,&conditions,&profiles,&v.updated_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }
    pub async fn delete_policy(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params("DELETE FROM client_policies WHERE id=$1", &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    fn map_profile(row: &wasi_pg_client::Row) -> Result<ClientPolicyProfile, OidcError> {
        let json = mapper::json_value(row, 4)?;
        let executors: Vec<ClientPolicyExecutor> = serde_json::from_value(json).map_err(|e| {
            OidcError::Internal(format!("invalid stored client policy executors: {e}"))
        })?;
        Ok(ClientPolicyProfile {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            description: mapper::opt_string(row, 3)?,
            executors,
            created_at: mapper::datetime(row, 5)?,
            updated_at: mapper::datetime(row, 6)?,
        })
    }
    fn map_policy(row: &wasi_pg_client::Row) -> Result<ClientPolicy, OidcError> {
        let conditions: Vec<ClientPolicyCondition> =
            serde_json::from_value(mapper::json_value(row, 6)?).map_err(|e| {
                OidcError::Internal(format!("invalid stored client policy conditions: {e}"))
            })?;
        let profile_ids: Vec<Uuid> =
            serde_json::from_value(mapper::json_value(row, 7)?).map_err(|e| {
                OidcError::Internal(format!("invalid stored client policy profiles: {e}"))
            })?;
        Ok(ClientPolicy {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            description: mapper::opt_string(row, 3)?,
            enabled: mapper::bool_(row, 4)?,
            priority: mapper::i32_(row, 5)?,
            conditions,
            profile_ids,
            created_at: mapper::datetime(row, 8)?,
            updated_at: mapper::datetime(row, 9)?,
        })
    }
}
