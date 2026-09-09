# Use case: connect an enterprise directory

[Documentation home](../README.md) · [User federation](../user-federation.md) · [Federation gateway](../federation-gateway-api.md)

Use this journey when LDAP or Active Directory remains the source of employee identities and passwords, or when browsers use Kerberos sign-in.

## Outcome

Directory users authenticate in the realm without copying their passwords into the hub, selected profile and group data synchronize, and directory outages have a tested response.

## A. Prepare the connection

1. Deploy the federation gateway where it can reach the directory.
2. Store directory bind credentials or Kerberos keytabs in the gateway.
3. Protect the gateway with HTTPS and a long shared secret.
4. Test the gateway's connection, authentication, user-listing, and Kerberos operations before onboarding users.

## B. Configure the provider

1. Open **User Federation**, select the realm, and add LDAP, Active Directory, or Kerberos.
2. Enter the gateway address and shared secret.
3. Configure the base DN, filter, stable external ID, username, email, profile, and group mappings.
4. Enable user import and group synchronization only when local records are required.
5. Save and choose **Test**.

![Configured enterprise directory providers](../assets/user-federation/providers.png)

## C. Pilot and synchronize

Test with a small directory group. Confirm first login, profile mapping, group membership, realm roles inherited through groups, MFA, and required actions. Run **Sync** and verify updates use the stable external ID even after a username change.

Enable email linking only after confirming that the directory controls and verifies those addresses. Test duplicate email handling before broad synchronization.

## D. Test failure and removal

Disable the provider and confirm the expected sign-in failure without deleting imported records. Test an invalid password, unavailable gateway, disabled directory user, removed group, and clock or keytab failure for Kerberos. Define whether departed users are disabled by synchronization or by a separate lifecycle workflow.

## Completion check

- Passwords and keytabs exist only in the systems that need them.
- Login, synchronization, rename, disablement, and group removal pass end to end.
- Provider priority and duplicate-account behavior are documented.
- Operators know how to disable the provider and inspect Audit during an outage.

