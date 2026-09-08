# Federation gateway contract

A federation gateway exposes directory and Kerberos operations over HTTPS. Every request uses `Content-Type: application/json` and `Authorization: Bearer <shared-secret>`.

The request always contains `provider_type` (`ldap`, `active_directory`, or `kerberos`) and `config`, the JSON object saved for the provider.

## Test a connection

`POST /v1/test`

```json
{"provider_type":"ldap","config":{"connection":"corporate-ldap"}}
```

Return `{"ok":true,"message":"Directory connection successful"}` after connecting and binding successfully. Return `ok: false` for a known configuration failure or an HTTP error when the gateway cannot complete the operation.

## Validate a directory password

`POST /v1/authenticate`

The request adds `identifier` and `password`. Return `{"authenticated":false}` for invalid credentials. On success, return `authenticated: true` and a user object.

## Validate a Kerberos token

`POST /v1/kerberos/verify`

The request adds `negotiate_token`, containing the base64 token after the HTTP `Negotiate` scheme. The gateway validates the SPNEGO/Kerberos ticket against its HTTP service key and resolves the principal to a directory user. Invalid, expired, replayed, incorrectly addressed, or unverifiable tickets return `{"authenticated":false}`.

## List users

`POST /v1/users`

The first request omits `cursor`. A response contains `users` and either an opaque `next_cursor` or `null`. Continue until the cursor is null.

```json
{
  "users": [
    {
      "external_id": "stable-directory-id",
      "username": "alice",
      "email": "alice@example.com",
      "dn": "uid=alice,ou=people,dc=example,dc=com",
      "given_name": "Alice",
      "family_name": "Martin",
      "display_name": "Alice Martin",
      "enabled": true,
      "groups": ["engineering"],
      "attributes": {"department":"engineering"}
    }
  ],
  "next_cursor": null
}
```

`external_id`, `username`, and `email` are required. The external ID must remain stable across renames. `attributes` must be a JSON object. Gateway responses should omit directory secrets and raw Kerberos material.
