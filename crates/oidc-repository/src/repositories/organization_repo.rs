use oidc_core::OidcError;
use oidc_core::models::{
    Organization, OrganizationDomain, OrganizationDomainKind, OrganizationGroupLink,
    OrganizationIdentityProviderLink, OrganizationInvitation, OrganizationInvitationStatus,
    OrganizationMember, OrganizationMembership, OrganizationMembershipKind,
};
use uuid::Uuid;

use crate::{Connection, mapper};

pub struct OrganizationRepo;

const COLUMNS: &str = "id, realm_id, name, alias, enabled, attributes, claim_attribute_names, redirect_url, created_at, updated_at";

impl OrganizationRepo {
    pub async fn find_by_id(
        &self,
        conn: &mut Connection,
        id: Uuid,
    ) -> Result<Option<Organization>, OidcError> {
        let sql =
            format!("SELECT {COLUMNS} FROM organizations WHERE id = $1 AND deleted_at IS NULL");
        conn.query_one_params(&sql, &[&id])
            .await
            .map_err(mapper::pg_err)?
            .map(|row| Self::map_organization(&row))
            .transpose()
    }

    pub async fn find_by_alias(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        alias: &str,
    ) -> Result<Option<Organization>, OidcError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM organizations \
             WHERE realm_id = $1 AND alias = $2 AND deleted_at IS NULL"
        );
        conn.query_one_params(&sql, &[&realm_id, &alias])
            .await
            .map_err(mapper::pg_err)?
            .map(|row| Self::map_organization(&row))
            .transpose()
    }

    pub async fn list(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Organization>, OidcError> {
        let pattern = search.map(|value| format!("%{}%", escape_like(value)));
        let (sql, params): (String, Vec<&dyn wasi_pg_client::ToSql>) = match pattern.as_ref() {
            Some(pattern) => (
                format!(
                    "SELECT {COLUMNS} FROM organizations \
                     WHERE realm_id = $1 AND deleted_at IS NULL \
                     AND (name ILIKE $2 ESCAPE '\\\\' OR alias ILIKE $2 ESCAPE '\\\\') \
                     ORDER BY name LIMIT $3 OFFSET $4"
                ),
                vec![&realm_id, pattern, &limit, &offset],
            ),
            None => (
                format!(
                    "SELECT {COLUMNS} FROM organizations \
                     WHERE realm_id = $1 AND deleted_at IS NULL \
                     ORDER BY name LIMIT $2 OFFSET $3"
                ),
                vec![&realm_id, &limit, &offset],
            ),
        };
        conn.query_params(&sql, &params)
            .await
            .map_err(mapper::pg_err)?
            .into_rows()
            .iter()
            .map(Self::map_organization)
            .collect()
    }

    pub async fn count(&self, conn: &mut Connection, realm_id: Uuid) -> Result<i64, OidcError> {
        let row = conn
            .query_one_params(
                "SELECT COUNT(*) FROM organizations WHERE realm_id = $1 AND deleted_at IS NULL",
                &[&realm_id],
            )
            .await
            .map_err(mapper::pg_err)?
            .ok_or_else(|| OidcError::Internal("organization count returned no row".into()))?;
        mapper::i64_(&row, 0)
    }

    pub async fn create(
        &self,
        conn: &mut Connection,
        organization: &Organization,
    ) -> Result<(), OidcError> {
        organization.validate()?;
        conn.execute_params(
            "INSERT INTO organizations \
             (id, realm_id, name, alias, enabled, attributes, claim_attribute_names, redirect_url, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &organization.id,
                &organization.realm_id,
                &organization.name,
                &organization.alias,
                &organization.enabled,
                &organization.attributes,
                &mapper::to_json_value_vec(&organization.claim_attribute_names),
                &organization.redirect_url,
                &organization.created_at,
                &organization.updated_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn update(
        &self,
        conn: &mut Connection,
        organization: &Organization,
    ) -> Result<(), OidcError> {
        organization.validate()?;
        conn.execute_params(
            "UPDATE organizations SET name = $1, enabled = $2, attributes = $3, claim_attribute_names = $4, \
             redirect_url = $5, updated_at = NOW() WHERE id = $6 AND deleted_at IS NULL",
            &[
                &organization.name,
                &organization.enabled,
                &organization.attributes,
                &mapper::to_json_value_vec(&organization.claim_attribute_names),
                &organization.redirect_url,
                &organization.id,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn delete(&self, conn: &mut Connection, id: Uuid) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE users SET deleted_at = NOW(), enabled = FALSE WHERE id IN (SELECT user_id FROM organization_memberships WHERE organization_id = $1 AND membership_kind = 'managed')",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        conn.execute_params(
            "UPDATE organizations SET deleted_at = NOW(), enabled = FALSE WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn add_domain(
        &self,
        conn: &mut Connection,
        domain: &OrganizationDomain,
    ) -> Result<(), OidcError> {
        domain.validate()?;
        let kind = match domain.kind {
            OrganizationDomainKind::Exact => "exact",
            OrganizationDomainKind::Wildcard => "wildcard",
        };
        let normalized = domain.domain.trim().to_ascii_lowercase();
        conn.execute_params(
            "INSERT INTO organization_domains \
             (id, organization_id, domain, kind, verified, verification_token_hash) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &domain.id,
                &domain.organization_id,
                &normalized,
                &kind,
                &domain.verified,
                &domain.verification_token_hash,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_domains(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationDomain>, OidcError> {
        conn.query_params(
            "SELECT id, organization_id, domain, kind, verified, verification_token_hash \
             FROM organization_domains WHERE organization_id = $1 ORDER BY domain",
            &[&organization_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(Self::map_domain)
        .collect()
    }

    pub async fn delete_domain(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        domain_id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "DELETE FROM organization_domains WHERE organization_id = $1 AND id = $2",
            &[&organization_id, &domain_id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    pub async fn verify_domain(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        domain_id: Uuid,
        token_hash: &str,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "UPDATE organization_domains SET verified = TRUE, verification_token_hash = NULL WHERE organization_id = $1 AND id = $2 AND verified = FALSE AND verification_token_hash = $3",
            &[&organization_id, &domain_id, &token_hash],
        ).await.map_err(mapper::pg_err)
    }

    pub async fn add_member(
        &self,
        conn: &mut Connection,
        membership: &OrganizationMembership,
    ) -> Result<(), OidcError> {
        let kind = match membership.kind {
            OrganizationMembershipKind::Managed => "managed",
            OrganizationMembershipKind::Unmanaged => "unmanaged",
        };
        conn.execute_params(
            "INSERT INTO organization_memberships \
             (organization_id, user_id, membership_kind, joined_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (organization_id, user_id) DO NOTHING",
            &[
                &membership.organization_id,
                &membership.user_id,
                &kind,
                &membership.joined_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OidcError> {
        let row = conn.query_one_params(
            "SELECT membership_kind FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
            &[&organization_id, &user_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .ok_or_else(|| OidcError::NotFound("organization member".into()))?;
        if mapper::string(&row, 0)? == "managed" {
            conn.execute_params(
                "UPDATE users SET deleted_at = NOW(), enabled = FALSE WHERE id = $1",
                &[&user_id],
            )
            .await
            .map_err(mapper::pg_err)?;
        }
        conn.execute_params(
            "DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
            &[&organization_id, &user_id],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_members(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>, OidcError> {
        conn.query_params(
            "SELECT u.id, u.email, u.username, u.given_name, u.family_name, u.enabled, \
                    om.membership_kind, om.joined_at \
             FROM organization_memberships om \
             JOIN users u ON u.id = om.user_id AND u.deleted_at IS NULL \
             WHERE om.organization_id = $1 ORDER BY u.email",
            &[&organization_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(Self::map_member)
        .collect()
    }

    pub async fn link_identity_provider(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        identity_provider_id: Uuid,
        redirect_on_email_domain: bool,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "INSERT INTO organization_identity_providers \
             (organization_id, identity_provider_id, redirect_on_email_domain) \
             VALUES ($1, $2, $3)",
            &[
                &organization_id,
                &identity_provider_id,
                &redirect_on_email_domain,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn unlink_identity_provider(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        identity_provider_id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "DELETE FROM organization_identity_providers \
             WHERE organization_id = $1 AND identity_provider_id = $2",
            &[&organization_id, &identity_provider_id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    pub async fn list_identity_providers(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationIdentityProviderLink>, OidcError> {
        conn.query_params(
            "SELECT oip.organization_id, ip.id, ip.alias, ip.display_name, ip.enabled, \
                    oip.redirect_on_email_domain \
             FROM organization_identity_providers oip \
             JOIN identity_providers ip ON ip.id = oip.identity_provider_id \
                  AND ip.deleted_at IS NULL \
             WHERE oip.organization_id = $1 ORDER BY ip.display_name",
            &[&organization_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(Self::map_identity_provider_link)
        .collect()
    }

    pub async fn link_group(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        group_id: Uuid,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "INSERT INTO organization_groups (organization_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&organization_id, &group_id],
        ).await.map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn unlink_group(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        group_id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "DELETE FROM organization_groups WHERE organization_id = $1 AND group_id = $2",
            &[&organization_id, &group_id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    pub async fn list_groups(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationGroupLink>, OidcError> {
        conn.query_params(
            "SELECT og.organization_id, g.id, g.name FROM organization_groups og JOIN groups g ON g.id = og.group_id AND g.deleted_at IS NULL WHERE og.organization_id = $1 ORDER BY g.name",
            &[&organization_id],
        ).await.map_err(mapper::pg_err)?.into_rows().iter().map(|row| Ok(OrganizationGroupLink {
            organization_id: mapper::uuid(row, 0)?, group_id: mapper::uuid(row, 1)?, name: mapper::string(row, 2)?,
        })).collect()
    }

    pub async fn find_user_group_names_and_roles(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<(Vec<String>, Vec<String>), OidcError> {
        let groups = conn.query_params(
            "SELECT DISTINCT g.name FROM organization_groups og JOIN groups g ON g.id = og.group_id AND g.deleted_at IS NULL JOIN user_groups ug ON ug.group_id = g.id WHERE og.organization_id = $1 AND ug.user_id = $2 ORDER BY g.name",
            &[&organization_id, &user_id],
        ).await.map_err(mapper::pg_err)?.into_rows().iter().map(|row| mapper::string(row, 0)).collect::<Result<Vec<_>, _>>()?;
        let roles = conn.query_params(
            "SELECT DISTINCT r.name FROM organization_groups og JOIN user_groups ug ON ug.group_id = og.group_id JOIN group_roles gr ON gr.group_id = og.group_id JOIN roles r ON r.id = gr.role_id AND r.deleted_at IS NULL WHERE og.organization_id = $1 AND ug.user_id = $2 ORDER BY r.name",
            &[&organization_id, &user_id],
        ).await.map_err(mapper::pg_err)?.into_rows().iter().map(|row| mapper::string(row, 0)).collect::<Result<Vec<_>, _>>()?;
        Ok((groups, roles))
    }

    pub async fn list_memberships_for_user(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<OrganizationMembership>, OidcError> {
        conn.query_params(
            "SELECT organization_id, user_id, membership_kind, joined_at \
             FROM organization_memberships WHERE user_id = $1 ORDER BY joined_at",
            &[&user_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(Self::map_membership)
        .collect()
    }

    pub async fn find_enabled_by_user_id(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<Vec<Organization>, OidcError> {
        let sql = "SELECT o.id, o.realm_id, o.name, o.alias, o.enabled, o.attributes, \
                    o.redirect_url, o.created_at, o.updated_at FROM organizations o \
             JOIN organization_memberships om ON om.organization_id = o.id \
             WHERE om.user_id = $1 AND o.enabled = TRUE AND o.deleted_at IS NULL \
             ORDER BY o.alias";
        conn.query_params(sql, &[&user_id])
            .await
            .map_err(mapper::pg_err)?
            .into_rows()
            .iter()
            .map(Self::map_organization)
            .collect()
    }

    /// Managed users cannot authenticate while their owning organization is disabled.
    pub async fn is_managed_user_blocked(
        &self,
        conn: &mut Connection,
        user_id: Uuid,
    ) -> Result<bool, OidcError> {
        let row = conn.query_one_params(
            "SELECT EXISTS(SELECT 1 FROM organization_memberships om JOIN organizations o ON o.id = om.organization_id WHERE om.user_id = $1 AND om.membership_kind = 'managed' AND (o.enabled = FALSE OR o.deleted_at IS NOT NULL))",
            &[&user_id],
        ).await.map_err(mapper::pg_err)?.ok_or_else(|| OidcError::Internal("managed membership check returned no row".into()))?;
        mapper::bool_(&row, 0)
    }

    pub async fn find_identity_provider_for_domain(
        &self,
        conn: &mut Connection,
        realm_id: Uuid,
        domain: &str,
    ) -> Result<Option<OrganizationIdentityProviderLink>, OidcError> {
        let rows = conn
            .query_params(
                "SELECT oip.organization_id, ip.id, ip.alias, ip.display_name, ip.enabled, \
                        oip.redirect_on_email_domain \
                 FROM organization_domains od \
                 JOIN organizations o ON o.id = od.organization_id \
                 JOIN organization_identity_providers oip ON oip.organization_id = o.id \
                 JOIN identity_providers ip ON ip.id = oip.identity_provider_id \
                 WHERE o.realm_id = $1 AND o.enabled = TRUE AND o.deleted_at IS NULL \
                   AND od.verified = TRUE AND oip.redirect_on_email_domain = TRUE \
                   AND ip.enabled = TRUE AND ip.deleted_at IS NULL \
                   AND ((od.kind = 'exact' AND lower(od.domain) = lower($2)) \
                     OR (od.kind = 'wildcard' AND (lower($2) = lower(od.domain) \
                         OR lower($2) LIKE '%.' || lower(od.domain)))) \
                 ORDER BY CASE od.kind WHEN 'exact' THEN 0 ELSE 1 END, length(od.domain) DESC \
                 LIMIT 2",
                &[&realm_id, &domain],
            )
            .await
            .map_err(mapper::pg_err)?
            .into_rows();
        if rows.len() > 1 {
            return Err(OidcError::Conflict(
                "email domain maps to more than one organization identity provider".into(),
            ));
        }
        rows.first()
            .map(Self::map_identity_provider_link)
            .transpose()
    }

    pub async fn create_invitation(
        &self,
        conn: &mut Connection,
        invitation: &OrganizationInvitation,
    ) -> Result<(), OidcError> {
        conn.execute_params(
            "UPDATE organization_invitations SET status = 'expired' \
             WHERE organization_id = $1 AND lower(email) = lower($2) \
               AND status = 'pending' AND expires_at <= NOW()",
            &[&invitation.organization_id, &invitation.email],
        )
        .await
        .map_err(mapper::pg_err)?;
        conn.execute_params(
            "INSERT INTO organization_invitations \
             (id, organization_id, email, first_name, last_name, token_hash, status, \
              invited_by, expires_at, created_at, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, NULL)",
            &[
                &invitation.id,
                &invitation.organization_id,
                &invitation.email,
                &invitation.first_name,
                &invitation.last_name,
                &invitation.token_hash,
                &invitation.invited_by,
                &invitation.expires_at,
                &invitation.created_at,
            ],
        )
        .await
        .map_err(mapper::pg_err)?;
        Ok(())
    }

    pub async fn list_invitations(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>, OidcError> {
        conn.query_params(
            "SELECT id, organization_id, email, first_name, last_name, token_hash, \
                    CASE WHEN status = 'pending' AND expires_at <= NOW() THEN 'expired' \
                         ELSE status END, invited_by, expires_at, created_at, accepted_at \
             FROM organization_invitations WHERE organization_id = $1 \
             ORDER BY created_at DESC",
            &[&organization_id],
        )
        .await
        .map_err(mapper::pg_err)?
        .into_rows()
        .iter()
        .map(Self::map_invitation)
        .collect()
    }

    pub async fn find_invitation_by_token_hash(
        &self,
        conn: &mut Connection,
        token_hash: &str,
    ) -> Result<Option<OrganizationInvitation>, OidcError> {
        conn.query_one_params(
            "SELECT id, organization_id, email, first_name, last_name, token_hash, status, \
                    invited_by, expires_at, created_at, accepted_at \
             FROM organization_invitations WHERE token_hash = $1",
            &[&token_hash],
        )
        .await
        .map_err(mapper::pg_err)?
        .map(|row| Self::map_invitation(&row))
        .transpose()
    }

    pub async fn revoke_invitation(
        &self,
        conn: &mut Connection,
        organization_id: Uuid,
        invitation_id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "UPDATE organization_invitations SET status = 'revoked' \
             WHERE organization_id = $1 AND id = $2 AND status = 'pending'",
            &[&organization_id, &invitation_id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    pub async fn accept_invitation(
        &self,
        conn: &mut Connection,
        invitation_id: Uuid,
    ) -> Result<u64, OidcError> {
        conn.execute_params(
            "UPDATE organization_invitations SET status = 'accepted', accepted_at = NOW() \
             WHERE id = $1 AND status = 'pending' AND expires_at > NOW()",
            &[&invitation_id],
        )
        .await
        .map_err(mapper::pg_err)
    }

    fn map_organization(row: &wasi_pg_client::Row) -> Result<Organization, OidcError> {
        Ok(Organization {
            id: mapper::uuid(row, 0)?,
            realm_id: mapper::uuid(row, 1)?,
            name: mapper::string(row, 2)?,
            alias: mapper::string(row, 3)?,
            enabled: mapper::bool_(row, 4)?,
            attributes: row.get(5).map_err(mapper::pg_err)?,
            claim_attribute_names: mapper::json_string_vec(row, 6)?,
            redirect_url: mapper::opt_string(row, 7)?,
            created_at: mapper::datetime(row, 8)?,
            updated_at: mapper::datetime(row, 9)?,
        })
    }

    fn map_domain(row: &wasi_pg_client::Row) -> Result<OrganizationDomain, OidcError> {
        let kind: String = mapper::string(row, 3)?;
        Ok(OrganizationDomain {
            id: mapper::uuid(row, 0)?,
            organization_id: mapper::uuid(row, 1)?,
            domain: mapper::string(row, 2)?,
            kind: if kind == "wildcard" {
                OrganizationDomainKind::Wildcard
            } else {
                OrganizationDomainKind::Exact
            },
            verified: mapper::bool_(row, 4)?,
            verification_token_hash: mapper::opt_string(row, 5)?,
        })
    }

    fn map_membership(row: &wasi_pg_client::Row) -> Result<OrganizationMembership, OidcError> {
        let kind: String = mapper::string(row, 2)?;
        Ok(OrganizationMembership {
            organization_id: mapper::uuid(row, 0)?,
            user_id: mapper::uuid(row, 1)?,
            kind: if kind == "managed" {
                OrganizationMembershipKind::Managed
            } else {
                OrganizationMembershipKind::Unmanaged
            },
            joined_at: mapper::datetime(row, 3)?,
        })
    }

    fn map_member(row: &wasi_pg_client::Row) -> Result<OrganizationMember, OidcError> {
        let kind: String = mapper::string(row, 6)?;
        Ok(OrganizationMember {
            user_id: mapper::uuid(row, 0)?,
            email: mapper::string(row, 1)?,
            username: mapper::opt_string(row, 2)?,
            given_name: mapper::opt_string(row, 3)?,
            family_name: mapper::opt_string(row, 4)?,
            enabled: mapper::bool_(row, 5)?,
            kind: if kind == "managed" {
                OrganizationMembershipKind::Managed
            } else {
                OrganizationMembershipKind::Unmanaged
            },
            joined_at: mapper::datetime(row, 7)?,
        })
    }

    fn map_identity_provider_link(
        row: &wasi_pg_client::Row,
    ) -> Result<OrganizationIdentityProviderLink, OidcError> {
        Ok(OrganizationIdentityProviderLink {
            organization_id: mapper::uuid(row, 0)?,
            identity_provider_id: mapper::uuid(row, 1)?,
            alias: mapper::string(row, 2)?,
            display_name: mapper::string(row, 3)?,
            enabled: mapper::bool_(row, 4)?,
            redirect_on_email_domain: mapper::bool_(row, 5)?,
        })
    }

    fn map_invitation(row: &wasi_pg_client::Row) -> Result<OrganizationInvitation, OidcError> {
        let status: String = mapper::string(row, 6)?;
        let status = match status.as_str() {
            "accepted" => OrganizationInvitationStatus::Accepted,
            "revoked" => OrganizationInvitationStatus::Revoked,
            "expired" => OrganizationInvitationStatus::Expired,
            _ => OrganizationInvitationStatus::Pending,
        };
        Ok(OrganizationInvitation {
            id: mapper::uuid(row, 0)?,
            organization_id: mapper::uuid(row, 1)?,
            email: mapper::string(row, 2)?,
            first_name: mapper::opt_string(row, 3)?,
            last_name: mapper::opt_string(row, 4)?,
            token_hash: mapper::string(row, 5)?,
            status,
            invited_by: mapper::opt_uuid(row, 7)?,
            expires_at: mapper::datetime(row, 8)?,
            created_at: mapper::datetime(row, 9)?,
            accepted_at: mapper::opt_datetime(row, 10)?,
        })
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
