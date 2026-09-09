# Use case: operate organization invitations end to end

[Documentation home](../README.md) · [Organizations](../organizations.md) · [Email delivery](../email-delivery.md)

Use this journey when a business customer invites people into an organization and the application depends on managed membership.

## Outcome

Invitation email reaches the intended recipient, acceptance creates or links the correct account, organization claims appear in tokens, and pending or active access can be withdrawn.

## A. Prepare the organization

1. Configure transactional email and test delivery.
2. Create the organization with a stable alias and optional application redirect URL.
3. Add and verify its email domain when domain routing is used.
4. Link required realm groups and roles.
5. Add `organization` to the application's allowed scopes.

## B. Invite and accept

Open **Organizations → Invitations**, enter the recipient, and send the time-limited invitation. Test all relevant recipient paths:

- an existing local account confirms with its password;
- an already signed-in local or federated account confirms through its session;
- a recipient without an account chooses a password and receives a verified managed account.

![Organization members, invitations, identity providers, and groups](../assets/organizations/organization-members-and-access.png)

After acceptance, confirm membership and request `organization`, `organization:{alias}`, or `organization:*` as appropriate. Validate the organization ID, alias, exposed attributes, groups, and roles in the token.

## C. Handle failures and expiry

If mail does not arrive, verify the address, pending invitation, delivery configuration, and provider logs. Revoke a pending invitation that was sent incorrectly. Send a new invitation after expiry; links are single use.

## D. Suspend or remove access

Disable the organization to block authentication and refresh for managed members, then revoke sessions when access must stop before existing access tokens expire. Removing a managed member or deleting the organization deletes that managed account. Existing realm users are unmanaged and survive membership removal.

## Completion check

- Email delivery, expiry, single use, and revocation have been tested.
- Existing, federated, and new-recipient acceptance behave as expected.
- Applications reject a non-member requesting the organization.
- Operators understand managed-account deletion and token-expiry behavior.

