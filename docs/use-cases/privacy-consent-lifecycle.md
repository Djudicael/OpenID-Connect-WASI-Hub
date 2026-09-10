# Use case: operate privacy and consent throughout an account lifecycle

[Documentation home](../README.md) · [Consent](../consent-and-application-access.md) · [User account console](../user-account-console.md)

Use this journey when applications need user-approved profile access and operators must handle access removal or account deletion predictably.

## Outcome

Applications request only needed scopes, users can inspect and revoke grants, and account removal considers sessions, offline access, organization ownership, and required retention.

## A. Minimize requested data

For each client, list the business purpose of every requested scope and mapped claim. Allow only those scopes on the client. Request additional scopes when the feature needs them instead of asking for all future access during first sign-in.

## B. Obtain meaningful consent

Show the purpose in the application before redirecting. The approval page displays the application and requested permissions. Handle denial without losing the user's work. Use `prompt=consent` when a fresh decision is required.

## C. Provide user control

Direct users to **My Account → Applications** to review scopes, sessions, and remove saved application access. Review and revoke durable grants separately under **Offline access** because browser logout does not remove them.

![Applications and approved access in My Account](../assets/user-account-console/applications.png)

## D. Handle an access-removal request

1. Disable the user when access must stop during review.
2. Revoke active sessions and offline grants.
3. Remove application consent and linked identities as requested.
4. Check organization membership before deletion: managed organization accounts may be deleted with their membership or organization, while pre-existing realm accounts remain independent.
5. Export or retain required business records outside the identity platform before deleting the identity.
6. Review Audit to confirm the administrative actions.

## Completion check

- Every scope and custom claim has a documented purpose.
- Consent denial, incremental consent, and revocation work end to end.
- Normal sessions and offline grants are handled separately.
- Account deletion ownership and external retention obligations are understood.

