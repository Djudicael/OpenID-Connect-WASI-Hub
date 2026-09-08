# Connect LDAP, Active Directory, and Kerberos

User federation lets people use an existing company directory account in a realm. LDAP and Active Directory users can sign in with their directory username and password. Kerberos users can use browser-integrated sign-in through HTTP Negotiate.

## Before you begin

Deploy a federation gateway that can reach the company directory and, for Kerberos, access the service keytab. The gateway must use HTTPS in production and require a long, random shared secret. The identity service never stores a directory user's password.

The gateway needs four operations: test a connection, validate a username and password, list directory users, and validate a Kerberos Negotiate token. See the [federation gateway contract](federation-gateway-api.md) when configuring or building the gateway.

## Add a directory

1. Open **User Federation**.
2. Select the realm whose users will use the directory.
3. Select **Add provider**.
4. Choose **LDAP**, **Active Directory**, or **Kerberos / SPNEGO**.
5. Enter the federation gateway URL and the shared gateway secret.
6. Enter the directory configuration as a JSON object, then save.
7. Select **Test** to verify the connection.

![Configured LDAP, Active Directory, and Kerberos providers](assets/user-federation/providers.png)

Providers are tried in priority order. A lower number is tried first. Disable a provider to stop new logins and synchronization without deleting its configuration.

## Directory configuration

The configuration is passed to the gateway on every operation. A gateway can use these values directly or use a `connection` value to select credentials held by the gateway.

For LDAP, a typical configuration is:

```json
{
  "connection": "corporate-ldap",
  "base_dn": "ou=people,dc=example,dc=com",
  "user_filter": "(uid={identifier})",
  "id_attribute": "entryUUID",
  "username_attribute": "uid",
  "email_attribute": "mail",
  "given_name_attribute": "givenName",
  "family_name_attribute": "sn",
  "group_attribute": "memberOf",
  "link_existing_users": false
}
```

Active Directory commonly uses `objectGUID`, `sAMAccountName`, and `userPrincipalName`. Kerberos configuration identifies the HTTP service principal and the directory attribute used to resolve the authenticated principal.

Keep bind passwords and keytabs in the gateway. Do not put them in the JSON configuration.

## Import and synchronize users

Enable **Import users** to create local account records for directory users. Imported records hold profile data and group membership but no local password.

- A successful first login imports the user immediately.
- **Sync** imports and updates every user returned by the gateway.
- **Synchronize groups** creates missing realm groups and assigns imported users to them.
- The provider row shows the most recent synchronization result and the number of linked users.

Email addresses are verified because they come from the trusted directory. If a local account already owns an imported email, the link is rejected by default. Set `link_existing_users` to `true` only after confirming that the directory controls those addresses.

## User sign-in

LDAP and Active Directory users enter their directory email or username on the normal sign-in page. Their password is checked by the gateway and is never copied into the local account.

For Kerberos, send the browser's Negotiate token to:

```text
POST /realms/{realm}/protocol/openid-connect/kerberos
Authorization: Negotiate <token>
Content-Type: application/json

{"client_id":"your-client"}
```

An invalid or missing token returns `401 Unauthorized` with `WWW-Authenticate: Negotiate`. A successful response creates the same browser session and tokens as other sign-in methods. The ID token records `ldap`, `active_directory`, or `kerberos` in its authentication methods.

Realm MFA and required actions still apply after directory or Kerberos authentication.

## Troubleshooting

- **Connection failed:** confirm the gateway URL, shared secret, server certificate, and that the gateway can reach the directory.
- **Valid credentials are rejected:** check the base DN, user filter, username mapping, provider priority, and that the directory returns a valid email address.
- **A user cannot be imported:** check for an existing local account with the same email or enable reviewed email linking.
- **Groups are missing:** enable group synchronization and confirm that the gateway returns group names.
- **Kerberos keeps prompting:** verify browser trusted-site settings, DNS, the HTTP service principal, keytab permissions, and clock synchronization.
