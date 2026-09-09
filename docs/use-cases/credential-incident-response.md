# Use case: respond to a compromised account or credential

[Documentation home](../README.md) · [Operations](../operations.md) · [User management](../user-management.md)

Use this journey when a user session, password, client secret, API key, recovery method, or offline grant may be exposed.

## Outcome

New access is stopped quickly, durable grants are handled explicitly, evidence is preserved, and replacement credentials restore only the required access.

## A. Identify the affected identity

Record the realm, user or client, affected applications, discovery time, and relevant request IDs. Review **Audit**, **Sessions**, **API Keys**, consent, and offline access without changing evidence first.

## B. Contain access

- For a user, disable the account and revoke active sessions and offline grants.
- For lost MFA, reset MFA after verifying the user through the approved recovery process.
- For an API key, revoke it immediately when exposure is confirmed. Rotation provides a 24-hour overlap and is intended for planned cutovers.
- For an OIDC client secret, disable the affected client to stop new tokens. Create a replacement client and credential before restoring the workload.
- Remove saved application consent when the application itself should no longer have access.

Already-issued access tokens remain usable until expiry unless the receiving API checks current session or grant state. Account for that window in containment.

## C. Recover safely

Reset the user password or enroll new MFA methods, restore only reviewed roles and groups, deploy replacement workload credentials, and re-enable access. Verify sign-in and API calls from a known device before closing the incident.

## D. Review

Inspect audit events and downstream logs for unexpected operations. Document the cause, affected period, actions taken, and any policy, workflow, or monitoring changes.

## Completion check

- Normal sessions and offline grants were considered separately.
- Every exposed secret has been revoked or replaced.
- Restored access has the minimum required permissions.
- The incident timeline and audit evidence are retained according to policy.

