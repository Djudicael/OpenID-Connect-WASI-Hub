# Use case: set up a delegated helpdesk

[Documentation home](../README.md) · [Delegated administration](../delegated-administration.md) · [User management](../user-management.md)

Use this journey when support staff need to find users, reset MFA, update profiles, or revoke sessions without full control of realms and applications.

## Outcome

Helpdesk users receive only the required administration permissions through a role, remain confined to their realm, and leave an audit trail for every action.

## A. Define duties

List the exact support tasks. A common starting set is:

- `users:read` to find and inspect users;
- `users:write` to update a user, required actions, or MFA state;
- `sessions:read` to inspect sessions;
- `sessions:revoke` to force reauthentication;
- `audit:read` when support staff may investigate events.

Omit impersonation unless the support process explicitly requires and governs it.

## B. Create and assign the role

1. Open **Roles**, choose **Add Role**, and create a realm role named `helpdesk`.
2. Enter the approved comma-separated permissions.
3. Create a `helpdesk-team` group and assign the role to it.
4. Add each support user to the group.

![Delegated administration role with explicit permissions](../assets/delegated-administration/create-role.png)

## C. Test the boundary

Sign in as a test helpdesk user and verify allowed tasks. Then attempt to manage a client, realm, API key, or another realm and confirm the action is forbidden.

## D. Operate support requests

Before changing an account, confirm the requester using your organization's support policy. Record the affected user and reason outside the platform when a ticketing record is required. Perform the smallest corrective action, then verify the corresponding event in **Audit**.

## E. Remove access

Remove a departing operator from the group and revoke their active sessions. Role changes apply to the next administration request, while already-issued tokens should still be revoked during urgent removal.

## Completion check

- Helpdesk users can perform every approved task.
- They cannot manage clients, realms, keys, or users in another realm.
- MFA reset revokes the affected user's sessions.
- Administrative changes appear in Audit with the correct actor.
- Removing group membership and sessions removes access.
