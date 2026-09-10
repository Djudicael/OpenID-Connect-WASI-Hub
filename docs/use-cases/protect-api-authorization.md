# Use case: protect an API with resource permissions

[Documentation home](../README.md) · [Authorization Services](../authorization-services.md) · [Application integration](../application-integration.md)

Use this journey when roles alone cannot express who may act on a particular record, document, project, or other protected resource.

## Outcome

The API registers its resources and scopes, policies decide which users qualify, and the API accepts only Requesting Party Tokens (RPTs) containing the required resource permission.

## A. Prepare the API client

1. Create a confidential client for the protected API.
2. Enable **UMA Permission Ticket** in its allowed grants.
3. Store the generated client secret in the API's secret manager.
4. Open **Authorization Services** and select that client as the resource server.

## B. Model access

1. Register a resource with a unique name, its protected URIs, and scopes such as `view`, `edit`, or `approve`.
2. Add an owner or non-secret resource attributes when a rule needs them.
3. Create user, role, group, client, owner, attribute, or time policies.
4. Create a permission that combines the resource, scopes, policies, and decision strategy.

![Resource permission combining resources, scopes, and policies](../assets/authorization-services/permissions.png)

## C. Request and enforce permission

1. Discover the UMA endpoints from `/realms/{realm}/.well-known/uma2-configuration`.
2. When access is missing, have the API create a single-use permission ticket for the resource and scopes.
3. Exchange the ticket with the user's access token for an RPT.
4. Retry the API request with the RPT.
5. Validate the RPT signature, issuer, audience, expiry, and `authorization.permissions` entry before returning the resource.

## D. Test denial and revocation

Test a matching user, a user missing the policy, an unrelated client, a wrong scope, an expired ticket, and a replayed ticket. Revoke the RPT under **RPT grants** and confirm subsequent evaluation or introspection rejects it.

## Completion check

- Each business operation maps to a resource scope.
- The API denies requests without the exact resource permission.
- Policy changes and RPT revocation have been tested.
- The API client secret never reaches a browser or mobile application.

