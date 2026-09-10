# Connect LDAP, Active Directory, and Kerberos

[Documentation home](README.md) · [Enterprise directory rollout](use-cases/enterprise-directory-rollout.md)

User federation lets people use an existing company directory account in a realm. LDAP and Active Directory can connect directly to the directory. A federation gateway remains available for existing installations and is required for Kerberos browser sign-in.

The hub never copies a directory user's password into the local account. It stores only the encrypted service-account credential used to search the directory.

## Add a direct LDAP or Active Directory provider

Before starting, obtain the directory hostname, port, base DN, service-account DN and password, and the attribute names used by your directory. For a private certificate authority, obtain its PEM certificate without the private key.

1. Open **User Federation** and select the realm.
2. Select **Add provider**.
3. Choose **LDAP** or **Active Directory**.
4. Select **Direct directory connection**.
5. Enter a secure directory URL:
   - `ldaps://directory.example.com:636` for LDAP over TLS;
   - `ldap+starttls://directory.example.com:389` for a StartTLS upgrade.
6. Enter the bind password. It is required when `bind_dn` is present in the directory configuration.
7. Review the directory configuration, then select **Save**.
8. Select **Test**. A successful test confirms the network connection, TLS verification, service bind, base DN, and a basic search.

![Configured direct and gateway directory providers](assets/user-federation/providers.png)

Use `ldap://` only for a deliberately unencrypted connection. Remote plain LDAP is rejected unless the configuration contains `"allow_insecure_transport": true`.

## LDAP configuration

The following example searches and imports standard LDAP person entries:

```json
{
  "base_dn": "ou=people,dc=example,dc=com",
  "bind_dn": "cn=oidc-service,ou=service,dc=example,dc=com",
  "user_filter": "(uid={identifier})",
  "sync_filter": "(objectClass=person)",
  "id_attribute": "entryUUID",
  "username_attribute": "uid",
  "email_attribute": "mail",
  "given_name_attribute": "givenName",
  "family_name_attribute": "sn",
  "display_name_attribute": "displayName",
  "group_attribute": "memberOf",
  "custom_attributes": ["departmentNumber"],
  "timeout_seconds": 10,
  "page_size": 500,
  "result_limit": 1000,
  "link_existing_users": false
}
```

`user_filter` must contain `{identifier}`. The sign-in value is escaped before it is inserted. `sync_filter` selects the population returned by **Sync**. `id_attribute` must remain stable when a username, email address, or DN changes.

`custom_attributes` copies the named directory attributes into the user's attributes object. These values can then be used by protocol mappers and authorization policies. Add only attributes that applications are allowed to receive.

An empty `bind_dn` requests an anonymous service bind. Use it only when the directory explicitly allows the required searches without a service account.

## Active Directory configuration

Select **Active Directory** to use defaults for common AD attributes:

```json
{
  "base_dn": "DC=example,DC=com",
  "bind_dn": "CN=OIDC Service,OU=Service Accounts,DC=example,DC=com",
  "user_filter": "(|(userPrincipalName={identifier})(sAMAccountName={identifier}))",
  "sync_filter": "(&(objectClass=user)(objectCategory=person))",
  "id_attribute": "objectGUID",
  "username_attribute": "sAMAccountName",
  "email_attribute": "mail",
  "given_name_attribute": "givenName",
  "family_name_attribute": "sn",
  "display_name_attribute": "displayName",
  "group_attribute": "memberOf",
  "enabled_attribute": "userAccountControl",
  "timeout_seconds": 10,
  "page_size": 500,
  "result_limit": 1000,
  "link_existing_users": false
}
```

The binary `objectGUID` becomes the stable linked-user ID. Accounts marked disabled through `userAccountControl` cannot sign in. Direct `memberOf` values are converted to group names.

## Trust a private certificate authority

Add the public CA certificate to the configuration when LDAPS or StartTLS uses a private CA:

```json
{
  "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

Keep the rest of the directory fields in the same object. The server certificate must still match the hostname in the directory URL and be valid at the time of the connection.

## Import and synchronize users

Enable **Import users** to create local profile records without local passwords.

- A successful first sign-in imports or updates that user.
- **Sync** reads directory users in pages and imports or updates them.
- **Synchronize groups** creates missing realm groups and assigns imported users to the groups returned by the directory.
- The provider row shows the most recent synchronization result and linked-user count.

If a local account already owns an imported email, linking is rejected. Set `link_existing_users` to `true` only after confirming that the directory controls and verifies those email addresses.

Providers are tried in priority order; a lower number runs first. Disable a provider to stop its sign-ins and synchronization while retaining its configuration and linked users.

## Use a federation gateway

Select **Federation gateway** when keeping an existing gateway deployment or configuring Kerberos/SPNEGO. Enter its HTTPS URL and shared secret. The non-secret JSON configuration is sent to the gateway on each operation. See the [gateway contract](federation-gateway-api.md).

For Kerberos, the gateway validates the browser's Negotiate ticket and resolves its principal. Passwords, keytabs, and raw tickets must never be placed in the JSON configuration.

## User sign-in

LDAP and Active Directory users enter the identifier accepted by the configured `user_filter` on the normal sign-in page. The hub searches for exactly one matching entry and verifies the password with a bind as that user. Realm MFA and required actions still apply.

Kerberos clients send their Negotiate token to:

```text
POST /realms/{realm}/protocol/openid-connect/kerberos
Authorization: Negotiate <token>
Content-Type: application/json

{"client_id":"your-client"}
```

## Troubleshooting

- **Connection failed:** confirm DNS, port access, the URL scheme, and that the directory accepts connections from the hub.
- **TLS validation failed:** confirm the URL hostname, certificate validity, certificate chain, and configured private CA.
- **Service bind failed:** verify `bind_dn`, replace the stored bind password, and confirm that the service account can search the base DN.
- **Valid credentials are rejected:** check the base DN, `user_filter`, username mapping, and that exactly one entry contains a valid email address.
- **Synchronization stops:** reduce `page_size`, narrow `sync_filter`, or raise `result_limit` within the supported limits.
- **A user cannot be imported:** check for a local account with the same email and review the account-linking policy.
- **Groups are missing:** enable group synchronization and confirm that `group_attribute` is returned for the service account.
- **Kerberos keeps prompting:** verify the gateway, browser trusted-site settings, DNS, service principal, keytab, and clock synchronization.
