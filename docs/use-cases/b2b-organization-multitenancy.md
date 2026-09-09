# Use case: build B2B organization multi-tenancy

[Documentation home](../README.md) · [Organizations](../organizations.md) · [Core concepts](../concepts.md)

Use this journey when several customer companies share one product and identity realm, while each company needs its own members, domain, identity provider, and tenant claim.

## Outcome

Each company is represented by an organization. Users can belong to one or several companies, invitations create managed members, enterprise identity providers route the correct users, and applications receive verified organization context in tokens.

## A. Prepare the shared realm and application

1. Create a realm for the B2B product population.
2. Register the product as an OIDC client.
3. Add `organization` to the client's allowed scopes.
4. Create realm groups and roles that represent product access.
5. Configure email delivery before inviting members.

## B. Create the first customer organization

1. Open **Organizations**, select the realm, and create the customer.
2. Choose a stable alias such as `acme`; applications use this value in scopes and claims.
3. Add non-secret attributes such as plan or region.
4. List only the attributes that applications may receive in tokens.
5. Set an invitation redirect URL when accepted members should land in the product.

![Organization settings, attributes, and verified domains](../assets/organizations/organization-settings-and-domains.png)

## C. Verify ownership and enterprise sign-in

1. Add the customer's email domain.
2. Publish the generated DNS TXT value and choose **Verify DNS** after propagation.
3. Create the customer's OIDC or SAML identity provider at realm level.
4. Link that provider to the organization.
5. Enable matching-domain redirection when email discovery should route users to it.

Only verified domains participate in domain-based routing.

## D. Add access structure

1. Link the realm groups used by this customer to the organization.
2. Assign product roles to those groups.
3. Add existing realm users as unmanaged members, or invite new managed members by email.
4. Confirm the invitation with a test recipient.

Managed accounts follow the organization's lifecycle. Existing realm accounts remain independent when organization membership is removed.

## E. Request tenant context

Use the scope that matches the application journey:

- `organization` chooses the only membership or asks the user when several exist.
- `organization:acme` requires the `acme` membership.
- `organization:*` returns every enabled membership.

Validate that the token's `organization` claim contains the expected alias, organization ID, exposed attributes, linked groups, and roles. The application should use the stable organization ID or alias as its tenant boundary and verify membership on each new token.

## F. Delegate customer administration

Create a delegated role with organization view, management, or membership permissions. Include the organization UUID in the permission when an administrator must manage only one customer, then assign the role to the customer administrator.

## G. Suspend or remove a customer

Disable the organization to block authentication and refresh for managed members. Existing access tokens remain valid until expiry, so revoke sessions when access must stop immediately. Before deleting an organization, review which managed accounts will also be deleted.

## Completion check

- The customer alias is stable and unique.
- Domain verification succeeds and routes only the intended addresses.
- Invitation email and acceptance work end to end.
- A member receives the correct organization claim and product roles.
- A non-member cannot request that organization.
- A delegated customer administrator cannot access another organization.
- Suspension and deletion behavior have been tested with managed and unmanaged users.
