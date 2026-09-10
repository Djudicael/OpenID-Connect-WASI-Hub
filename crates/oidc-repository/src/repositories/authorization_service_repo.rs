use oidc_core::OidcError;
use oidc_core::models::{
    AuthorizationPermission, AuthorizationPolicy, PermissionTicket, ProtectedResource, RptGrant,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{Connection, mapper};

pub struct AuthorizationServiceRepo;

impl AuthorizationServiceRepo {
    pub async fn list_resources(
        &self,
        conn: &mut Connection,
        server_id: Uuid,
    ) -> Result<Vec<ProtectedResource>, OidcError> {
        conn.query_params(
            "SELECT id,realm_id,resource_server_id,owner_id,name,display_name,resource_type,uris,scopes,attributes,icon_uri,created_at,updated_at FROM authorization_resources WHERE resource_server_id=$1 ORDER BY name",
            &[&server_id],
        ).await.map_err(mapper::pg_err)?.into_rows().iter().map(map_resource).collect()
    }

    pub async fn find_resource(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<ProtectedResource>, OidcError> {
        conn.query_one_params(
            "SELECT id,realm_id,resource_server_id,owner_id,name,display_name,resource_type,uris,scopes,attributes,icon_uri,created_at,updated_at FROM authorization_resources WHERE id=$1",
            &[&id],
        ).await.map_err(mapper::pg_err)?.map(|row| map_resource(&row)).transpose()
    }

    pub async fn find_resource_by_uri(
        &self,
        conn: &mut Connection,
        server_id: Uuid,
        uri: &str,
    ) -> Result<Option<ProtectedResource>, OidcError> {
        conn.query_one_params(
            "SELECT id,realm_id,resource_server_id,owner_id,name,display_name,resource_type,uris,scopes,attributes,icon_uri,created_at,updated_at FROM authorization_resources WHERE resource_server_id=$1 AND uris ? $2 LIMIT 1",
            &[&server_id, &uri],
        ).await.map_err(mapper::pg_err)?.map(|row| map_resource(&row)).transpose()
    }

    pub async fn create_resource(
        &self,
        conn: &mut Connection,
        item: &ProtectedResource,
    ) -> Result<(), OidcError> {
        let uris = serde_json::json!(item.uris);
        let scopes = serde_json::json!(item.scopes);
        conn.execute_params(
            "INSERT INTO authorization_resources(id,realm_id,resource_server_id,owner_id,name,display_name,resource_type,uris,scopes,attributes,icon_uri) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[&item.id,&item.realm_id,&item.resource_server_id,&item.owner_id,&item.name,&item.display_name,&item.resource_type,&uris,&scopes,&item.attributes,&item.icon_uri],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update_resource(
        &self,
        conn: &mut Connection,
        item: &ProtectedResource,
    ) -> Result<(), OidcError> {
        let uris = serde_json::json!(item.uris);
        let scopes = serde_json::json!(item.scopes);
        conn.execute_params(
            "UPDATE authorization_resources SET owner_id=$1,name=$2,display_name=$3,resource_type=$4,uris=$5,scopes=$6,attributes=$7,icon_uri=$8,updated_at=NOW() WHERE id=$9",
            &[&item.owner_id,&item.name,&item.display_name,&item.resource_type,&uris,&scopes,&item.attributes,&item.icon_uri,&item.id],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_resource(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params("DELETE FROM authorization_resources WHERE id=$1", &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_policies(
        &self,
        conn: &mut Connection,
        server_id: Uuid,
    ) -> Result<Vec<AuthorizationPolicy>, OidcError> {
        conn.query_params("SELECT id,realm_id,resource_server_id,name,description,policy_type,logic,config,created_at,updated_at FROM authorization_policies WHERE resource_server_id=$1 ORDER BY name", &[&server_id])
            .await.map_err(mapper::pg_err)?.into_rows().iter().map(map_policy).collect()
    }

    pub async fn find_policy(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<AuthorizationPolicy>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,resource_server_id,name,description,policy_type,logic,config,created_at,updated_at FROM authorization_policies WHERE id=$1", &[&id])
            .await.map_err(mapper::pg_err)?.map(|row| map_policy(&row)).transpose()
    }

    pub async fn create_policy(
        &self,
        conn: &mut Connection,
        item: &AuthorizationPolicy,
    ) -> Result<(), OidcError> {
        item.validate().map_err(OidcError::InvalidInput)?;
        conn.execute_params("INSERT INTO authorization_policies(id,realm_id,resource_server_id,name,description,policy_type,logic,config) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&item.id,&item.realm_id,&item.resource_server_id,&item.name,&item.description,&item.policy_type,&item.logic,&item.config]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update_policy(
        &self,
        conn: &mut Connection,
        item: &AuthorizationPolicy,
    ) -> Result<(), OidcError> {
        item.validate().map_err(OidcError::InvalidInput)?;
        conn.execute_params("UPDATE authorization_policies SET name=$1,description=$2,policy_type=$3,logic=$4,config=$5,updated_at=NOW() WHERE id=$6",
            &[&item.name,&item.description,&item.policy_type,&item.logic,&item.config,&item.id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_policy(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params("DELETE FROM authorization_policies WHERE id=$1", &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_permissions(
        &self,
        conn: &mut Connection,
        server_id: Uuid,
    ) -> Result<Vec<AuthorizationPermission>, OidcError> {
        conn.query_params("SELECT id,realm_id,resource_server_id,name,description,resources,scopes,policies,decision_strategy,created_at,updated_at FROM authorization_permissions WHERE resource_server_id=$1 ORDER BY name", &[&server_id])
            .await.map_err(mapper::pg_err)?.into_rows().iter().map(map_permission).collect()
    }

    pub async fn find_permission(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<AuthorizationPermission>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,resource_server_id,name,description,resources,scopes,policies,decision_strategy,created_at,updated_at FROM authorization_permissions WHERE id=$1", &[&id])
            .await.map_err(mapper::pg_err)?.map(|row| map_permission(&row)).transpose()
    }

    pub async fn create_permission(
        &self,
        conn: &mut Connection,
        item: &AuthorizationPermission,
    ) -> Result<(), OidcError> {
        item.validate().map_err(OidcError::InvalidInput)?;
        let resources = serde_json::json!(item.resources);
        let scopes = serde_json::json!(item.scopes);
        let policies = serde_json::json!(item.policies);
        conn.execute_params("INSERT INTO authorization_permissions(id,realm_id,resource_server_id,name,description,resources,scopes,policies,decision_strategy) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[&item.id,&item.realm_id,&item.resource_server_id,&item.name,&item.description,&resources,&scopes,&policies,&item.decision_strategy]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update_permission(
        &self,
        conn: &mut Connection,
        item: &AuthorizationPermission,
    ) -> Result<(), OidcError> {
        item.validate().map_err(OidcError::InvalidInput)?;
        let resources = serde_json::json!(item.resources);
        let scopes = serde_json::json!(item.scopes);
        let policies = serde_json::json!(item.policies);
        conn.execute_params("UPDATE authorization_permissions SET name=$1,description=$2,resources=$3,scopes=$4,policies=$5,decision_strategy=$6,updated_at=NOW() WHERE id=$7",
            &[&item.name,&item.description,&resources,&scopes,&policies,&item.decision_strategy,&item.id]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete_permission(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<(), OidcError> {
        conn.execute_params("DELETE FROM authorization_permissions WHERE id=$1", &[&id])
            .await
            .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn create_ticket(
        &self,
        conn: &mut Connection,
        ticket: &PermissionTicket,
        token_hash: &str,
    ) -> Result<(), OidcError> {
        let scopes = serde_json::json!(ticket.scopes);
        conn.execute_params("INSERT INTO authorization_permission_tickets(id,token_hash,realm_id,resource_server_id,requester_id,resource_id,scopes,granted,used,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[&ticket.id,&token_hash,&ticket.realm_id,&ticket.resource_server_id,&ticket.requester_id,&ticket.resource_id,&scopes,&ticket.granted,&ticket.used,&ticket.expires_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn find_active_ticket(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<PermissionTicket>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,resource_server_id,requester_id,resource_id,scopes,granted,used,expires_at,created_at FROM authorization_permission_tickets WHERE token_hash=$1 AND used=FALSE AND expires_at>NOW()", &[&token_hash])
            .await.map_err(mapper::pg_err)?.map(|row| map_ticket(&row)).transpose()
    }

    pub async fn find_ticket(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<PermissionTicket>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,resource_server_id,requester_id,resource_id,scopes,granted,used,expires_at,created_at FROM authorization_permission_tickets WHERE id=$1", &[&id])
            .await.map_err(mapper::pg_err)?.map(|row| map_ticket(&row)).transpose()
    }

    pub async fn consume_ticket(
        &self,
        conn: &mut Connection,
        id: Uuid,
        granted: bool,
    ) -> Result<bool, OidcError> {
        Ok(conn.execute_params("UPDATE authorization_permission_tickets SET used=TRUE,granted=$1 WHERE id=$2 AND used=FALSE AND expires_at>NOW()", &[&granted,&id]).await.map_err(mapper::pg_err)? == 1)
    }

    pub async fn list_tickets(
        &self,
        conn: &mut Connection,
        server_id: Uuid,
    ) -> Result<Vec<PermissionTicket>, OidcError> {
        conn.query_params("SELECT id,realm_id,resource_server_id,requester_id,resource_id,scopes,granted,used,expires_at,created_at FROM authorization_permission_tickets WHERE resource_server_id=$1 ORDER BY created_at DESC", &[&server_id])
            .await.map_err(mapper::pg_err)?.into_rows().iter().map(map_ticket).collect()
    }

    pub async fn revoke_ticket(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE authorization_permission_tickets SET used=TRUE,granted=FALSE WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn create_rpt(
        &self,
        conn: &mut Connection,
        item: &RptGrant,
    ) -> Result<(), OidcError> {
        conn.execute_params("INSERT INTO authorization_rpt_grants(id,realm_id,resource_server_id,subject_id,client_id,permissions,revoked,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&item.id,&item.realm_id,&item.resource_server_id,&item.subject_id,&item.client_id,&item.permissions,&item.revoked,&item.expires_at]).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn find_active_rpt(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<RptGrant>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,resource_server_id,subject_id,client_id,permissions,revoked,expires_at,created_at FROM authorization_rpt_grants WHERE id=$1 AND revoked=FALSE AND expires_at>NOW()", &[&id])
            .await.map_err(mapper::pg_err)?.map(|row| map_rpt(&row)).transpose()
    }

    pub async fn find_rpt(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<RptGrant>, OidcError> {
        conn.query_one_params("SELECT id,realm_id,resource_server_id,subject_id,client_id,permissions,revoked,expires_at,created_at FROM authorization_rpt_grants WHERE id=$1", &[&id])
            .await.map_err(mapper::pg_err)?.map(|row| map_rpt(&row)).transpose()
    }

    pub async fn list_rpts(
        &self,
        conn: &mut Connection,
        server_id: Uuid,
    ) -> Result<Vec<RptGrant>, OidcError> {
        conn.query_params("SELECT id,realm_id,resource_server_id,subject_id,client_id,permissions,revoked,expires_at,created_at FROM authorization_rpt_grants WHERE resource_server_id=$1 ORDER BY created_at DESC", &[&server_id])
            .await.map_err(mapper::pg_err)?.into_rows().iter().map(map_rpt).collect()
    }

    pub async fn revoke_rpt(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE authorization_rpt_grants SET revoked=TRUE WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn cleanup_expired(&self, conn: &mut Connection) -> Result<u64, OidcError> {
        let tickets = conn
            .execute(
                "DELETE FROM authorization_permission_tickets WHERE expires_at<NOW() OR (used=TRUE AND created_at<NOW()-INTERVAL '1 day')",
            )
            .await
            .map_err(mapper::pg_err)?;
        let rpts = conn
            .execute(
                "DELETE FROM authorization_rpt_grants WHERE expires_at<NOW() OR (revoked=TRUE AND created_at<NOW()-INTERVAL '1 day')",
            )
            .await
            .map_err(mapper::pg_err)?;
        Ok(tickets.rows_affected().unwrap_or(0) + rpts.rows_affected().unwrap_or(0))
    }
}

fn strings(row: &wasi_pg_client::Row, index: usize) -> Result<Vec<String>, OidcError> {
    let value = row.get::<Value>(index).map_err(mapper::pg_err)?;
    serde_json::from_value(value).map_err(|error| OidcError::Internal(error.to_string()))
}

fn uuids(row: &wasi_pg_client::Row, index: usize) -> Result<Vec<Uuid>, OidcError> {
    let value = row.get::<Value>(index).map_err(mapper::pg_err)?;
    serde_json::from_value(value).map_err(|error| OidcError::Internal(error.to_string()))
}

fn map_resource(row: &wasi_pg_client::Row) -> Result<ProtectedResource, OidcError> {
    Ok(ProtectedResource {
        id: mapper::uuid(row, 0)?,
        realm_id: mapper::uuid(row, 1)?,
        resource_server_id: mapper::uuid(row, 2)?,
        owner_id: mapper::opt_uuid(row, 3)?,
        name: mapper::string(row, 4)?,
        display_name: mapper::opt_string(row, 5)?,
        resource_type: mapper::opt_string(row, 6)?,
        uris: strings(row, 7)?,
        scopes: strings(row, 8)?,
        attributes: row.get(9).map_err(mapper::pg_err)?,
        icon_uri: mapper::opt_string(row, 10)?,
        created_at: mapper::datetime(row, 11)?,
        updated_at: mapper::datetime(row, 12)?,
    })
}
fn map_policy(row: &wasi_pg_client::Row) -> Result<AuthorizationPolicy, OidcError> {
    Ok(AuthorizationPolicy {
        id: mapper::uuid(row, 0)?,
        realm_id: mapper::uuid(row, 1)?,
        resource_server_id: mapper::uuid(row, 2)?,
        name: mapper::string(row, 3)?,
        description: mapper::opt_string(row, 4)?,
        policy_type: mapper::string(row, 5)?,
        logic: mapper::string(row, 6)?,
        config: row.get(7).map_err(mapper::pg_err)?,
        created_at: mapper::datetime(row, 8)?,
        updated_at: mapper::datetime(row, 9)?,
    })
}
fn map_permission(row: &wasi_pg_client::Row) -> Result<AuthorizationPermission, OidcError> {
    Ok(AuthorizationPermission {
        id: mapper::uuid(row, 0)?,
        realm_id: mapper::uuid(row, 1)?,
        resource_server_id: mapper::uuid(row, 2)?,
        name: mapper::string(row, 3)?,
        description: mapper::opt_string(row, 4)?,
        resources: uuids(row, 5)?,
        scopes: strings(row, 6)?,
        policies: uuids(row, 7)?,
        decision_strategy: mapper::string(row, 8)?,
        created_at: mapper::datetime(row, 9)?,
        updated_at: mapper::datetime(row, 10)?,
    })
}
fn map_ticket(row: &wasi_pg_client::Row) -> Result<PermissionTicket, OidcError> {
    Ok(PermissionTicket {
        id: mapper::uuid(row, 0)?,
        realm_id: mapper::uuid(row, 1)?,
        resource_server_id: mapper::uuid(row, 2)?,
        requester_id: mapper::opt_uuid(row, 3)?,
        resource_id: mapper::uuid(row, 4)?,
        scopes: strings(row, 5)?,
        granted: mapper::bool_(row, 6)?,
        used: mapper::bool_(row, 7)?,
        expires_at: mapper::datetime(row, 8)?,
        created_at: mapper::datetime(row, 9)?,
    })
}
fn map_rpt(row: &wasi_pg_client::Row) -> Result<RptGrant, OidcError> {
    Ok(RptGrant {
        id: mapper::uuid(row, 0)?,
        realm_id: mapper::uuid(row, 1)?,
        resource_server_id: mapper::uuid(row, 2)?,
        subject_id: mapper::uuid(row, 3)?,
        client_id: mapper::uuid(row, 4)?,
        permissions: row.get(5).map_err(mapper::pg_err)?,
        revoked: mapper::bool_(row, 6)?,
        expires_at: mapper::datetime(row, 7)?,
        created_at: mapper::datetime(row, 8)?,
    })
}
