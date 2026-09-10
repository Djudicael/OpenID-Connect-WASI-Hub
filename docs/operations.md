# Operate and recover the identity platform

[Documentation home](README.md) · [Realm backup and restore](realm-import-export.md) · [Deployment proxy](../deploy/proxy-cookbook.md)

This guide covers the recurring tasks visible in the administration console. Deployment-specific monitoring, database backup, and secret management should also follow your hosting platform's procedures.

## Monitor availability

Use these unauthenticated health endpoints from the platform:

| Endpoint | Use |
|---|---|
| `/health/live` | Process or component liveness |
| `/health/ready` | Readiness to receive traffic |
| `/health` | General health check |

Keep health checks separate from user sign-in checks. A successful liveness response does not prove that an application callback, email provider, or external identity provider is configured correctly.

## Review sessions

Open **Sessions** to see client, grant, scopes, expiry, and status. Revoke one session or select several and choose **Revoke Selected** when users must authenticate again.

Revoking a browser session does not remove a durable offline grant. Review [offline access](offline-access.md) separately.

## Investigate audit events

Open **Audit** and filter by event type or actor ID. Events identify the actor type, actor, target type, target, and time. Use this information to answer who changed an object and when.

Keep application and gateway request logs with the response `X-Request-ID` so an administration or protocol request can be correlated with backend activity. Never place credentials, cookies, or token values in correlation fields.

## Remove expired records

Open **Maintenance** and choose **Run Cleanup Now**. The operation permanently removes expired sessions, password-reset tokens, email-verification tokens, account-recovery tokens, device codes, authorization codes, and pushed authorization requests. The page reports how many rows were removed from each area.

Run cleanup according to your data-volume and retention needs. Review the result rather than repeatedly running it when no expired data exists.

## Process workflow timers

Scheduled workflows and delayed actions need a periodic authenticated call. Follow [Process scheduled and delayed actions](workflows.md#process-scheduled-and-delayed-actions) to create the dedicated key and configure the scheduler.

## Back up realms

Use [password-protected realm export](realm-import-export.md) before significant configuration changes and on a regular schedule that matches your recovery objective. Store the archive password separately from the archive.

Realm export is a portable identity configuration and data archive. Continue to back up PostgreSQL with database-native tooling for full operational recovery, including runtime history and data intentionally excluded from realm transfer.

## Rotate secrets and keys

- Rotate administration API keys from **API Keys** and update each workload secret.
- Replace confidential-client credentials according to application policy. The console cannot recover or reset an existing generated secret, so create a replacement client, switch the application, verify it, and then disable the old client.
- Keep deterministic runtime encryption and signing material in the deployment secret manager and consistent across replicas.
- Test token validation and sign-in after any signing-key or public issuer change.

## Incident checklist

1. Disable or revoke the affected user, client, API key, or session.
2. Preserve relevant audit events, request IDs, gateway logs, and timestamps.
3. Rotate any credential that may have been exposed.
4. Review realm boundaries, client redirect URIs, role assignments, active sessions, and offline grants.
5. Restore configuration from a verified realm archive only when rollback is required.
6. Exercise sign-in, token validation, administration, and email journeys before closing the incident.
