# Register and connect OIDC applications

[Documentation home](README.md) · [Getting started](getting-started.md) · [Service accounts and agents](service-accounts-and-agents.md)

Each application is a client inside one realm. The application should use the realm discovery document instead of hard-coding individual protocol endpoints.

## Choose the client type and flow

| Application | Client type | Grant |
|---|---|---|
| Browser single-page application | Public | Authorization Code with S256 PKCE |
| Mobile or desktop application | Public | Authorization Code with S256 PKCE |
| Server-rendered web application | Confidential | Authorization Code; PKCE can remain enabled |
| TV, terminal, or input-constrained device | Public or confidential as appropriate | Device Authorization |
| Backend service or unattended agent | Confidential | Client Credentials |
| Application asking for approval on another device | Confidential | CIBA |

Never put a confidential-client secret in browser JavaScript, a mobile package, a desktop binary, or a public repository.

## Register an interactive application

1. Open **Clients**, select the realm, and choose **Add Client**.
2. Enter a stable **Client ID** and human-readable name.
3. Choose **Public** when the application cannot protect a secret; otherwise choose **Confidential**.
4. Select **Authorization Code** and **Refresh Token** when the application needs renewable sessions.
5. Keep **PKCE Required** enabled.
6. Enter every callback URI exactly, one per line. Use HTTPS outside local development.
7. Select the allowed scopes and create the client.

When a confidential-client secret is generated, the console copies it at creation time. Save it immediately in the application's secret store. The existing value cannot be recovered from the client details page.

## Configure the OIDC library

Use the realm name in the issuer URL:

```text
https://identity.example.com/realms/{realm}
```

The discovery document is:

```text
https://identity.example.com/realms/{realm}/.well-known/openid-configuration
```

Configure the client ID, exact redirect URI, requested scopes, and client secret only when the application is confidential. The OIDC library must validate the issuer, signature, audience, state, and nonce. Use the S256 PKCE method.

## Choose scopes and claims

Start with `openid`. Request `profile`, `email`, `phone`, or `address` only when the application uses that information. Request `roles` when the application reads standard role claims, `organization` for tenant context, and `offline_access` only for a user-approved durable grant.

Use [client scopes and protocol mappers](client-scopes-and-protocol-mappers.md) to add reusable application claims and API audiences. Use [client roles](client-and-composite-roles.md) for application-specific authorization.

## Configure logout

Open the client details page to configure front-channel logout, back-channel logout, and allowed post-logout redirect addresses when the application supports them. The application should clear its local session even when a remote logout notification cannot be delivered.

## Test before production

1. Sign in with a normal test user and complete consent and required actions.
2. Confirm an unregistered redirect address is rejected.
3. Confirm a token from another realm or with another audience is rejected by the application.
4. Confirm role changes appear after a new token is issued.
5. Confirm logout, session expiry, and revoked sessions return the user to authentication.
6. Review **Audit** and **Sessions** for the test activity.

For stricter registration rules across all clients, configure [client policies](client-policies.md).

