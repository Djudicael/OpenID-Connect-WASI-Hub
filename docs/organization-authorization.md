# Client-qualified organization authorization

[Organizations](organizations.md) remain the membership authority. Applications
can use an additive authorization object in organization claims to avoid trusting
ambiguous role/group display names. No new organization membership database or
password store is required in the consuming application.

## Claim contract

Allow `organization` in the public client's scopes; request `organization:*` or
one existing `organization:<alias>` through the normal PKCE flow. Each selected
organization adds:

```json
{
  "authorization": {
    "version": 1,
    "client_id": "10000000-0000-4000-8000-000000000001",
    "teams": [{"id":"20000000-0000-4000-8000-000000000001","name":"Operations"}],
    "roles": [{"id":"30000000-0000-4000-8000-000000000001","name":"project-editor"}]
  }
}
```

The client ID here is its database UUID, not the public OAuth identifier. Team IDs
are organization-linked realm group UUIDs to which the current member belongs.
Roles are direct roles attached to those groups **for the requesting client**.
Deleted groups/roles, other clients and unrelated realm roles are excluded.
Composite-role inheritance is not expanded in this qualified object. Existing
organization fields, including legacy `groups` and `roles` names, remain additive
compatibility fields; they are not the qualified authorization object.

Consumers must pin issuer, audience, client UUID and role UUIDs, verify token
signatures and use stable IDs rather than names/aliases. Claim budgets are 16
selected organizations and 64 teams/roles per organization; over-budget issuance
fails rather than silently truncating grants. Select one organization for users
with many memberships.

## Current authorization and revocation

UserInfo re-reads current memberships, group assignments and direct client roles.
It rejects disabled/deleted realms, disabled users, blocked managed users and
expired/revoked sessions or token families. A removed organization scope target produces no organization
grant. Repository failures remain server failures, not stale authorization.
Consumers needing next-request revocation can intersect signed claims with fresh
UserInfo for the same subject/client. New grants then require token refresh;
in-flight requests are not retroactively cancelled. Do not cache stale grants
through provider outages.

## Server-to-server active status and team directory

For project API keys and bounded workers, configure both:

```dotenv
OIDC_ORGANIZATION_STATUS_REALM=example
OIDC_ORGANIZATION_STATUS_TOKEN=<private-random-64-hex-capability>
```

Without either variable the endpoint is absent; configuring only one fails
startup. Use a different credential from telemetry export or administration.

`GET /api/v1/authorization/realms/example/organizations/<uuid>/status?teams=true`
accepts this capability as a single Bearer header. Wrong realm, credential or
duplicate authorization headers return 404. Successful responses are `no-store`:

```json
{"organization_id":"20000000-0000-4000-8000-000000000001","active":true,"teams":[]}
```

`active` requires an enabled, undeleted organization and realm. `teams=true`
includes up to 256 undeleted, organization-linked same-realm groups (IDs/names),
not users, roles, credentials or membership details. Over-budget directory or
database failure returns 503; the operation is bounded to three seconds with a
two-second SQL statement timeout. Keep this capability exclusively server-side.
It grants no write/admin permission and is not an end-user organization API.

The handler and repository use the native/WASI shared implementation. Observatory's
local Rust CLI provisions dedicated test client roles/capability and exercises the
real WASI Hub through public-client browser sessions. Platform deployment and
external scheduling are separate acceptance boundaries.
