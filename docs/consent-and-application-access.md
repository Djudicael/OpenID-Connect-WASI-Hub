# Manage consent and application access

[Documentation home](README.md) · [User account console](user-account-console.md) · [Offline access](offline-access.md)

Consent records which scopes a user approved for one application. The approval page appears for a new grant, additional scopes, `prompt=consent`, and every request for offline access.

## What the user sees

After authentication and required actions, the approval page names the application and lists the requested permissions. The user can allow or deny the request. A denial returns control to the application with an access-denied result.

Applications should request scopes when they need them and explain the resulting capability in their own interface. Avoid requesting profile data or durable access that the feature does not use.

## Reuse an existing approval

When the user already approved all requested scopes, a later authorization request can continue without another approval page. `prompt=consent` forces a new decision. A silent `prompt=none` request returns `consent_required` when approval is missing.

Requesting an additional scope requires approval for the updated set. Offline access always requires an interactive approval even when other scopes were previously granted.

## Review or remove access

1. Sign in and open **My Account**.
2. Open **Applications**.
3. Review each application's scopes and active session count.
4. Choose **Remove access** to delete the saved approval and revoke that application's active sessions.

The next authorization request must ask for approval again. Review offline grants separately under **Offline access**; browser sign-out alone does not remove them.

## Application checklist

- Show why each requested permission is needed before starting authorization.
- Handle denial without losing the user's work.
- Use incremental scopes rather than requesting every future permission initially.
- Provide an application-side disconnect action in addition to **My Account**.
- Treat revoked sessions and refresh failures as a requirement to sign in again.

