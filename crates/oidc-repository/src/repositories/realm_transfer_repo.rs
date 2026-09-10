use oidc_core::OidcError;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{Connection, mapper};

pub struct RealmTransferRepo;

struct TableSpec {
    name: &'static str,
    export_sql: &'static str,
}

const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "users",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM users WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "clients",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM clients WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "client_policy_profiles",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM client_policy_profiles WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "client_policies",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.priority,t.id), '[]'::jsonb) FROM (SELECT * FROM client_policies WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "workflows",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY lower(t.name),t.id), '[]'::jsonb) FROM (SELECT * FROM workflows WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "ciba_client_configs",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT cc.* FROM ciba_client_configs cc JOIN clients c ON c.id=cc.client_id WHERE c.realm_id=$1) t",
    },
    TableSpec {
        name: "signing_keys",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM signing_keys WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "scopes",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM scopes WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "client_scopes",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT cs.* FROM client_scopes cs JOIN clients c ON c.id=cs.client_id WHERE c.realm_id=$1) t",
    },
    TableSpec {
        name: "realm_signing_keys",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT * FROM realm_signing_keys WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "identity_providers",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM identity_providers WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "federated_identities",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM federated_identities WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "roles",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM roles WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "groups",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM groups WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "user_roles",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT ur.* FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "user_groups",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT ug.* FROM user_groups ug JOIN users u ON u.id=ug.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "group_roles",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT gr.* FROM group_roles gr JOIN groups g ON g.id=gr.group_id WHERE g.realm_id=$1) t",
    },
    TableSpec {
        name: "role_composites",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT rc.* FROM role_composites rc JOIN roles r ON r.id=rc.parent_role_id WHERE r.realm_id=$1) t",
    },
    TableSpec {
        name: "protocol_mappers",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT pm.* FROM protocol_mappers pm JOIN scopes s ON s.id=pm.scope_id WHERE s.realm_id=$1) t",
    },
    TableSpec {
        name: "organizations",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM organizations WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "organization_domains",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT d.* FROM organization_domains d JOIN organizations o ON o.id=d.organization_id WHERE o.realm_id=$1) t",
    },
    TableSpec {
        name: "organization_memberships",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT m.* FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id WHERE o.realm_id=$1) t",
    },
    TableSpec {
        name: "organization_identity_providers",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT oi.* FROM organization_identity_providers oi JOIN organizations o ON o.id=oi.organization_id WHERE o.realm_id=$1) t",
    },
    TableSpec {
        name: "organization_invitations",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT i.* FROM organization_invitations i JOIN organizations o ON o.id=i.organization_id WHERE o.realm_id=$1) t",
    },
    TableSpec {
        name: "organization_groups",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT og.* FROM organization_groups og JOIN organizations o ON o.id=og.organization_id WHERE o.realm_id=$1) t",
    },
    TableSpec {
        name: "user_totp_credentials",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT c.* FROM user_totp_credentials c JOIN users u ON u.id=c.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "user_webauthn_credentials",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT c.* FROM user_webauthn_credentials c JOIN users u ON u.id=c.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "user_recovery_codes",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT c.* FROM user_recovery_codes c JOIN users u ON u.id=c.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "user_consents",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM user_consents WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "user_required_actions",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT a.* FROM user_required_actions a JOIN users u ON u.id=a.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "user_terms_acceptances",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT a.* FROM user_terms_acceptances a JOIN users u ON u.id=a.user_id WHERE u.realm_id=$1) t",
    },
    TableSpec {
        name: "api_keys",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM api_keys WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "authorization_resources",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM authorization_resources WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "authorization_policies",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM authorization_policies WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "authorization_permissions",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM authorization_permissions WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "user_federation_providers",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM user_federation_providers WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
    TableSpec {
        name: "federated_directory_users",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT d.* FROM federated_directory_users d JOIN user_federation_providers p ON p.id=d.provider_id WHERE p.realm_id=$1) t",
    },
    TableSpec {
        name: "saml_realm_keys",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t)), '[]'::jsonb) FROM (SELECT * FROM saml_realm_keys WHERE realm_id=$1) t",
    },
    TableSpec {
        name: "saml_service_providers",
        export_sql: "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb) FROM (SELECT * FROM saml_service_providers WHERE realm_id=$1 AND deleted_at IS NULL) t",
    },
];

const INSERT_ORDER: &[&str] = &[
    "users",
    "clients",
    "client_policy_profiles",
    "client_policies",
    "workflows",
    "ciba_client_configs",
    "signing_keys",
    "scopes",
    "realm_signing_keys",
    "identity_providers",
    "roles",
    "groups",
    "organizations",
    "user_federation_providers",
    "saml_realm_keys",
    "saml_service_providers",
    "client_scopes",
    "federated_identities",
    "user_roles",
    "user_groups",
    "group_roles",
    "role_composites",
    "protocol_mappers",
    "organization_domains",
    "organization_memberships",
    "organization_identity_providers",
    "organization_invitations",
    "organization_groups",
    "user_totp_credentials",
    "user_webauthn_credentials",
    "user_recovery_codes",
    "user_consents",
    "user_required_actions",
    "user_terms_acceptances",
    "api_keys",
    "authorization_resources",
    "authorization_policies",
    "authorization_permissions",
    "federated_directory_users",
];

impl RealmTransferRepo {
    pub async fn export(&self, conn: &mut Connection, realm_id: Uuid) -> Result<Value, OidcError> {
        let realm = conn
            .query_one_params(
                "SELECT to_jsonb(t) FROM (SELECT * FROM realms WHERE id=$1 AND deleted_at IS NULL) t",
                &[&realm_id],
            )
            .await
            .map_err(mapper::pg_err)?
            .ok_or_else(|| OidcError::NotFound("realm".into()))?
            .get::<Value>(0)
            .map_err(mapper::pg_err)?;
        let mut tables = Map::new();
        for spec in TABLES {
            let value = conn
                .query_one_params(spec.export_sql, &[&realm_id])
                .await
                .map_err(mapper::pg_err)?
                .ok_or_else(|| OidcError::Internal(format!("failed to export {}", spec.name)))?
                .get::<Value>(0)
                .map_err(mapper::pg_err)?;
            tables.insert(spec.name.into(), value);
        }
        Ok(serde_json::json!({"realm": realm, "tables": tables}))
    }

    pub async fn find_realm_for_import(
        &self,
        conn: &mut Connection,
        id: Uuid,
        name: &str,
    ) -> Result<Option<Uuid>, OidcError> {
        let row = conn
            .query_one_params(
                "SELECT id FROM realms WHERE id=$1 OR lower(name)=lower($2) ORDER BY (id=$1) DESC LIMIT 1",
                &[&id, &name],
            )
            .await
            .map_err(mapper::pg_err)?;
        row.map(|r| r.get::<Uuid>(0).map_err(mapper::pg_err))
            .transpose()
    }

    pub async fn clear_realm(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
    ) -> Result<(), OidcError> {
        for sql in [
            "DELETE FROM audit_events WHERE realm_id=$1",
            "DELETE FROM password_reset_tokens WHERE realm_id=$1",
            "DELETE FROM email_verification_tokens WHERE realm_id=$1",
            "DELETE FROM account_recovery_tokens WHERE realm_id=$1",
            "DELETE FROM authorization_codes WHERE realm_id=$1",
            "DELETE FROM pushed_authorization_requests WHERE realm_id=$1",
            "DELETE FROM device_codes WHERE realm_id=$1",
            "DELETE FROM ciba_authentication_requests WHERE realm_id=$1",
            "DELETE FROM social_login_states WHERE realm_id=$1",
            "DELETE FROM federated_identities WHERE realm_id=$1",
            "DELETE FROM mfa_ceremonies WHERE realm_id=$1",
            "DELETE FROM required_action_sessions WHERE realm_id=$1",
            "DELETE FROM authorization_permission_tickets WHERE realm_id=$1",
            "DELETE FROM authorization_rpt_grants WHERE realm_id=$1",
            "DELETE FROM saml_pending_requests WHERE realm_id=$1",
            "DELETE FROM saml_assertion_replays WHERE realm_id=$1",
            "DELETE FROM sessions WHERE realm_id=$1",
            "DELETE FROM organizations WHERE realm_id=$1",
            "DELETE FROM user_federation_providers WHERE realm_id=$1",
            "DELETE FROM saml_service_providers WHERE realm_id=$1",
            "DELETE FROM identity_providers WHERE realm_id=$1",
            "DELETE FROM workflows WHERE realm_id=$1",
            "DELETE FROM client_policies WHERE realm_id=$1",
            "DELETE FROM client_policy_profiles WHERE realm_id=$1",
            "DELETE FROM authorization_permissions WHERE realm_id=$1",
            "DELETE FROM authorization_policies WHERE realm_id=$1",
            "DELETE FROM authorization_resources WHERE realm_id=$1",
            "DELETE FROM api_keys WHERE realm_id=$1",
            "DELETE FROM users WHERE realm_id=$1",
            "DELETE FROM groups WHERE realm_id=$1",
            "DELETE FROM roles WHERE realm_id=$1",
            "DELETE FROM scopes WHERE realm_id=$1",
            "DELETE FROM clients WHERE realm_id=$1",
            "DELETE FROM signing_keys WHERE realm_id=$1",
            "DELETE FROM realm_signing_keys WHERE realm_id=$1",
            "DELETE FROM saml_realm_keys WHERE realm_id=$1",
        ] {
            conn.execute_params(sql, &[&realm_id])
                .await
                .map_err(mapper::pg_err)?;
        }
        Ok(())
    }

    pub async fn insert_snapshot(
        &self,
        conn: &mut Connection,
        realm: &Value,
        tables: &Map<String, Value>,
        replace: bool,
    ) -> Result<(), OidcError> {
        let realm_json = realm.clone();
        if replace {
            conn.execute_params(
                "UPDATE realms r SET name=x.name,display_name=x.display_name,enabled=x.enabled,config=x.config,created_at=x.created_at,updated_at=x.updated_at,deleted_at=NULL FROM jsonb_populate_record(NULL::realms,$1::jsonb) x WHERE r.id=x.id",
                &[&realm_json],
            ).await.map_err(mapper::pg_err)?;
        } else {
            conn.execute_params(
                "INSERT INTO realms SELECT * FROM jsonb_populate_record(NULL::realms,$1::jsonb)",
                &[&realm_json],
            )
            .await
            .map_err(mapper::pg_err)?;
        }
        for table in INSERT_ORDER {
            let rows = tables
                .get(*table)
                .cloned()
                .unwrap_or_else(|| Value::Array(vec![]));
            if !rows.as_array().is_some_and(|v| v.is_empty()) {
                let sql = format!(
                    "INSERT INTO {table} SELECT * FROM jsonb_populate_recordset(NULL::{table},$1::jsonb)"
                );
                conn.execute_params(&sql, &[&rows])
                    .await
                    .map_err(mapper::pg_err)?;
            }
        }
        Ok(())
    }
}
