# Use case: launch a production application

[Documentation home](../README.md) · [Application integration](../application-integration.md) · [Client policies](../client-policies.md)

Use this journey to move an OIDC application from development to production with separate credentials, strict callbacks, tested authorization, and a rollback path.

## Outcome

Production has its own client, secrets and claims are limited, invalid tokens are rejected, and operations can disable the integration without affecting other environments.

## A. Separate environments

Create a different client for development, staging, and production. Give each a recognizable name, exact HTTPS redirect and post-logout addresses, and only its own credentials. Use a public client for installed or browser-only applications and a confidential client only where a server can protect the secret.

## B. Establish the contract

1. Enable only the required grant types.
2. Allow only used scopes.
3. Create client roles for application permissions.
4. Add protocol mappers for required claims and the API audience.
5. Apply client policies for redirect, PKCE, grant, scope, or security-profile requirements.

## C. Validate in staging

Test first login, returning login, MFA and required actions, consent denial, role denial, token renewal, logout, session revocation, identity-provider failure, and wrong redirect URI. The application must validate issuer, signature, audience, expiry, state, and nonce.

## D. Release and observe

Deploy production configuration through the workload's secret manager. Confirm discovery and signing keys, then perform a normal-user smoke test. Review **Sessions** and **Audit** during rollout.

## E. Replace or roll back

For a confidential client credential change, create a replacement client, deploy and verify it, then disable the old client. Roll back by restoring the previous application release while its client remains enabled. Disable a faulty client to stop new authorization and token issuance.

## Completion check

- Environment clients and credentials are independent.
- Redirects, scopes, roles, claims, and audiences match the production contract.
- Negative authentication and authorization tests pass.
- Credential replacement, client disablement, and application rollback are documented.

