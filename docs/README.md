# OpenID Connect WASI Hub documentation

Use this page to choose a goal. The guides describe the administration console unless they explicitly show an API request.

## Start here

1. [Understand realms, organizations, users, and applications](concepts.md).
2. [Set up your first realm, user, and application](getting-started.md).
3. Choose a use case below or open the feature guide for the task you need.

## Use cases

### People and tenants

| Goal | Start with |
|---|---|
| Manage employees or members from onboarding through offboarding | [Manage a workforce user lifecycle](use-cases/workforce-user-lifecycle.md) |
| Automate employee onboarding, access changes, and offboarding | [Automate joiner, mover, and leaver processes](use-cases/joiner-mover-leaver-automation.md) |
| Give each business customer its own members and sign-in rules | [Build B2B organization multi-tenancy](use-cases/b2b-organization-multitenancy.md) |
| Invite and manage organization members | [Operate organization invitations](use-cases/organization-invitation-lifecycle.md) |
| Connect an LDAP, Active Directory, or Kerberos population | [Connect an enterprise directory](use-cases/enterprise-directory-rollout.md) |
| Let people sign in through an upstream OIDC or SAML provider | [Connect an external identity provider](use-cases/external-identity-provider-rollout.md) |
| Operate a customer-facing identity population | [Build a customer identity realm](use-cases/customer-identity.md) |

### Applications, services, and APIs

| Goal | Start with |
|---|---|
| Add sign-in to a browser or server-rendered web application | [Connect a web application](use-cases/web-application-sso.md) |
| Prepare and release an application to production | [Launch a production application](use-cases/production-application-launch.md) |
| Connect mobile, desktop, terminal, or constrained applications | [Connect mobile, desktop, and command-line applications](use-cases/mobile-desktop-cli.md) |
| Authenticate a backend service without a person | [Connect a backend service](use-cases/backend-service.md) |
| Give an automation agent the correct identity and access | [Choose an identity for an agent](use-cases/agent-identity.md) |
| Protect individual API resources with policies | [Protect an API with resource permissions](use-cases/protect-api-authorization.md) |

### Security and operations

| Goal | Start with |
|---|---|
| Introduce MFA, passkeys, recovery, and step-up checks | [Roll out MFA and passkeys safely](use-cases/mfa-rollout.md) |
| Contain and recover from an exposed account or credential | [Respond to a compromised credential](use-cases/credential-incident-response.md) |
| Give support staff limited administration access | [Set up a delegated helpdesk](use-cases/delegated-helpdesk.md) |
| Prepare controlled full-administrator recovery | [Set up delegated and emergency administration](use-cases/emergency-administration.md) |
| Manage consent, privacy, access removal, and account deletion | [Operate a privacy and consent lifecycle](use-cases/privacy-consent-lifecycle.md) |
| Restore a damaged realm or move it to another deployment | [Back up, migrate, and recover a realm](use-cases/realm-disaster-recovery.md) |

## Administer people and access

- [Users, groups, roles, sessions, and offboarding](user-management.md)
- [User account console](user-account-console.md)
- [Passwords and account recovery](passwords-and-recovery.md)
- [Multi-factor authentication](multi-factor-authentication.md)
- [Required actions and sign-in flows](authentication-flows.md)
- [Client and composite roles](client-and-composite-roles.md)
- [Delegated administration](delegated-administration.md)
- [User lifecycle workflows](workflows.md)

## Configure tenants and identity sources

- [Organizations](organizations.md)
- [LDAP, Active Directory, and Kerberos federation](user-federation.md)
- [Federation gateway contract](federation-gateway-api.md)
- [SAML applications and identity providers](saml.md)
- [External OIDC and SAML identity providers](identity-providers.md)
- [Realm themes, localization, and email templates](realm-themes-localization-email.md)
- [Transactional email delivery](email-delivery.md)

## Connect applications, services, and agents

- [Register OIDC applications](application-integration.md)
- [Service accounts and agent identities](service-accounts-and-agents.md)
- [Administration API keys](api-keys.md)
- [Client scopes and protocol mappers](client-scopes-and-protocol-mappers.md)
- [Client policies](client-policies.md)
- [Offline access](offline-access.md)
- [Consent and application access](consent-and-application-access.md)
- [CIBA sign-in approval](ciba.md)

## Protect APIs

- [Application roles and effective role claims](client-and-composite-roles.md)
- [Token claim and audience mapping](client-scopes-and-protocol-mappers.md)
- [Authorization Services and UMA](authorization-services.md)

## Operate and recover the platform

- [Operations, sessions, audit, cleanup, and recovery](operations.md)
- [Back up, restore, or move a realm](realm-import-export.md)
- [Production proxy configurations](../deploy/proxy-cookbook.md)
- [Runtime configuration and build instructions](../README.md#quick-start)

## Feature coverage

The [feature status matrix](../tempo.md) distinguishes completed, limited, and missing capabilities.
