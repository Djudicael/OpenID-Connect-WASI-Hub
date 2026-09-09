# Use case: connect an external identity provider

[Documentation home](../README.md) · [Identity providers](../identity-providers.md) · [SAML](../saml.md)

Use this journey when users sign in through another OpenID Connect or SAML identity provider.

## Outcome

Users are redirected to the upstream provider, linked to the correct realm identity, and returned to the application without unsafe automatic account linking.

## A. Establish trust

1. Choose OIDC or SAML and obtain the upstream issuer or metadata.
2. Create the provider in the target realm.
3. Register the hub callback address at the upstream provider.
4. For OIDC, store the client secret securely. For SAML, verify the imported signing certificates.
5. Decide whether first login may create a new realm user.

## B. Decide account-linking rules

Enable email linking only when the upstream provider supplies a verified address and your organization trusts that assurance. Otherwise require an existing signed-in account to link the identity. Ensure users retain another sign-in method before unlinking their last external identity.

## C. Add organization routing when needed

Create and verify the organization's email domain, link the realm identity provider to the organization, and enable matching-domain redirection. New accounts created through that link become managed organization members; pre-existing linked accounts remain unmanaged.

## D. Test the complete journey

Test first login, returning login, logout, a disabled local user, denied upstream access, changed upstream attributes, duplicate email, provider outage, and an invalid or replayed SAML response. Confirm organization membership and token claims after sign-in.

## Completion check

- Callback addresses, issuer, audience, destination, and signatures are verified.
- Automatic user creation and email linking follow an approved policy.
- Users can recover when the upstream provider is unavailable.
- Disabling the provider stops new external sign-ins without unexpectedly deleting users.

