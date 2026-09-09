# Choose the right identity boundary

[Documentation home](README.md) · [Getting started](getting-started.md) · [Use cases](README.md#use-cases)

The hub separates isolation, business membership, human identity, application identity, and administrative automation. Choosing the right object first keeps permissions and token claims understandable.

## Realm

A realm is the main security boundary. It owns users, applications, signing keys, sessions, roles, scopes, organizations, themes, and policies. Tokens issued by one realm use that realm's issuer and signing keys.

Create separate realms when populations need independent administrators, token issuers, security policy, or cryptographic isolation. Do not create a realm for every customer when those customers share the same applications and realm policy; use organizations for that case.

## Organization

An organization is a business tenant inside a realm. It can have members, verified email domains, invitations, linked identity providers, groups, roles, and attributes exposed in organization claims.

Use organizations for a B2B product where one person may belong to one or several customer companies. Applications remain realm resources and request the `organization` scope to learn which organization the user is using.

## Group and role

A group collects users and can inherit roles. A role represents access. Realm roles apply across a realm; client roles belong to one application. Composite roles include other roles.

Use groups for organizational structure such as `engineering` or `support-emea`. Use roles for decisions such as `invoice-reader` or `ticket-editor`. Assign roles to groups when many users need the same access.

## User account

A user is a person who signs in. Users may be created locally, invited through an organization, or imported from an identity provider or directory. Their interactive session can satisfy password, MFA, consent, and required-action checks.

Do not create a normal user for unattended software. A user credential adds password and account lifecycle risks and makes audit records look like a person performed the action.

## OIDC client

An OIDC client represents an application or workload that requests tokens.

- A **public client** cannot safely keep a secret. Browser, mobile, desktop, and command-line applications normally use Authorization Code with PKCE or Device Authorization.
- A **confidential client** can keep a secret or private key. Server-rendered web applications use Authorization Code; backend services and unattended agents use Client Credentials.

The resulting access token is for the application's APIs. It is not automatically an administration credential for the hub.

## API key

An API key authorizes automation against the hub's administration API. It belongs to one realm and carries explicit permissions such as `users:read` or `workflows:execute`.

Use an API key for provisioning jobs, workflow schedulers, and administrative scripts. Keep it out of browser and mobile applications. The complete value is shown only when the key is created or rotated.

## Pick an identity for software

| Software needs to | Use |
|---|---|
| Call its own protected business API without a user | Confidential OIDC client with Client Credentials |
| Act after a person explicitly signs in | Authorization Code with PKCE and the user's token |
| Continue user-approved access after browser logout | Authorization Code with approved `offline_access` |
| Ask a user to approve from another signed-in device | CIBA |
| Manage hub users, organizations, or workflows | Realm API key with only the required administration permissions |

