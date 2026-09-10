# Set up your first identity realm

[Documentation home](README.md) · [Core concepts](concepts.md) · [Connect an application](application-integration.md)

This path takes a new administrator from the first sign-in to a working application login.

## Before you begin

You need a running hub behind its browser-facing proxy, the administrator address printed by the deployment, and the initial administrator credentials supplied during setup. For local development these are `DEFAULT_EMAIL` and `DEFAULT_PASSWORD` in the local `.env` file.

For production deployment and required runtime secrets, follow the [runtime instructions](../README.md#production-deployment) and [proxy cookbook](../deploy/proxy-cookbook.md).

## 1. Sign in and create a realm

1. Open the administration console and sign in.
2. Open **Realms** and choose **Add Realm**.
3. Enter a stable realm name and a clear display name.
4. Open the new realm to review its enabled state and presentation settings.

The realm name becomes part of protocol URLs. Treat it as a stable identifier after applications are connected.

## 2. Set the security baseline

1. Open **Password Policies**, select the realm, and set length and character requirements appropriate for your users.
2. Open the realm and configure required email, profile, MFA, terms, or step-up checks under its authentication-flow settings.
3. Configure [email delivery](email-delivery.md) before enabling flows that send verification, reset, or invitation links.
4. If support staff will administer the realm, create delegated roles instead of giving every operator full `admin` permission.

## 3. Create a test user

1. Open **Users**, select the realm, and choose **Add User**.
2. Enter an email address, initial password, and optional profile details.
3. Open the new user and add **Update password** and **Verify email** under **Required actions** when those checks are part of onboarding.
4. Add the user to a group or assign a role when the application uses role-based access.

New local users begin with an unverified email address. The enabled state controls whether they may authenticate.

## 4. Register an application

1. Open **Clients** and choose **Add Client**.
2. Select the same realm as the user.
3. For a browser or mobile application, choose **Public**, enable **Authorization Code**, and keep **PKCE Required** enabled.
4. Enter every allowed callback address exactly, one per line.
5. Select the scopes the application needs and create the client.

Server applications that can keep credentials may use a confidential client. See [Register OIDC applications](application-integration.md) for each application type.

## 5. Configure discovery in the application

Give the application this issuer discovery address, replacing `{realm}` with the realm name:

```text
https://identity.example.com/realms/{realm}/.well-known/openid-configuration
```

Use the client ID created in the console, the exact redirect URI, Authorization Code flow, and S256 PKCE. Let the application's OIDC library discover the authorization, token, UserInfo, logout, and signing-key endpoints.

## 6. Verify the complete journey

1. Start sign-in from the application.
2. Confirm that the browser is sent to the expected realm and branded page.
3. Sign in as the test user and complete any required actions.
4. Confirm that the application validates the issuer, signature, audience, state, and nonce.
5. Confirm that the token contains only the scopes, roles, and custom claims the application needs.
6. Sign out and verify both the application session and identity session behave as intended.

If login fails, first compare the requested redirect URI and scope with the client configuration. Then review **Audit**, the user's enabled state, required actions, and active realm.

