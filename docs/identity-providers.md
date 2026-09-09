# Connect an external identity provider

[Documentation home](README.md) · [SAML](saml.md) · [Organizations](organizations.md)

An external identity provider lets users authenticate through another OIDC or SAML system. Directory federation is configured separately under **User Federation**.

## Connect an OIDC provider

1. Register the hub as an application with the external provider and record its issuer, client ID, and client secret.
2. In the hub, open **Identity Providers**, select the realm, and choose **Add Identity Provider**.
3. Enter a stable alias, choose **OIDC**, and enter the issuer URL, client ID, client secret, and requested scopes.
4. Choose whether the first successful login may create a realm user.
5. Enable linking by email only when the upstream provider's verified-email assurance and your account-linking policy make that safe.
6. Create the provider and test with a non-production account.

Use the callback address supplied by the hub configuration when registering it at the upstream provider. The issuer must be reachable from the running backend.

## Connect a SAML provider

Choose **SAML 2.0** and paste the identity-provider metadata XML. Follow the [SAML guide](saml.md#connect-an-external-saml-identity-provider) for signing, attribute mapping, replay protection, and logout.

## Link a provider to an organization

Create the realm provider first, then open the organization and link it under **Identity providers**. A verified organization email domain can route matching users to that provider. New users created through the linked provider become managed organization members; pre-existing linked accounts remain unmanaged.

## Test lifecycle behavior

Verify first login, returning login, disabled users, provider outage, account linking, organization membership, and logout. Confirm that removing a provider does not remove users unexpectedly and that users retain another sign-in method before unlinking their last external identity.

## Troubleshooting

- Confirm the provider issuer and callback address match exactly.
- Confirm the client secret and requested scopes are valid upstream.
- Review **Audit** and runtime logs for the failed callback.
- When organization routing fails, confirm the domain is verified and the provider is linked to that organization.
- When an existing account is not linked, review the email-linking setting and upstream email assurance.

