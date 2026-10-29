# Choose the access-token signing algorithm

[Documentation home](README.md) · [Backend service authentication](use-cases/backend-service.md)

The Hub publishes both RSA and Ed25519 public keys in its global and per-realm
JWKS. Publishing an Ed25519 key does not by itself make access tokens use it:
the default remains RS256 for compatibility with existing resource servers.

Set the following on every native or WASI Hub instance before starting it to
issue Ed25519 access tokens:

```text
OIDC_ACCESS_TOKEN_SIGNING_ALG=EdDSA
```

Accepted values are exactly `RS256` and `EdDSA`. An absent setting uses `RS256`;
an invalid value is rejected when the token service is constructed. Configure
the same value across replicas and restart them consistently. This setting
applies to access tokens across this Hub instance, including realm-specific
token services and the `client_credentials` flow. It does not change ID tokens,
logout tokens, client assertions, key publication or the existing key-storage
requirements. Both signing keys must still be configured as before.

Before enabling EdDSA, verify that every affected resource server accepts it,
or use a dedicated Hub deployment for those clients. Previously issued RS256
tokens are not re-signed; the Hub's verifier and JWKS continue to support them.
Resource servers choosing to accept only EdDSA will reject those older tokens.
Switching the setting back to RS256 restores the previous issuance behavior.

For an agentic coordinator, configure the `agents` realm and confidential
service clients with `client_credentials`, `client_secret_post`, and the
appropriate allowed/default or optional scopes:

| Client purpose | Scope |
| --- | --- |
| Definition/run administration | `agentic:operate` |
| Bounded dispatch | `agentic:dispatch` |
| Pending activities and result delivery | `agentic:activities` |

Assign an audience protocol mapper for `agentic-coordinator` to the relevant
client scopes, targeting access tokens. The coordinator validates the exact
realm issuer and audience rather than accepting a token just because its
signature is valid. See [client scopes and protocol mappers](client-scopes-and-protocol-mappers.md).

Realm discovery is at `/realms/agents/.well-known/openid-configuration` and
publishes `/realms/agents/protocol/openid-connect/certs` and the corresponding
token endpoint. Resource servers should discover these URLs from the configured
issuer, cache public keys with bounded freshness and support overlapping keys
during rotation. Private signing keys and client secrets remain server-side.

The Rust token service also exposes `with_access_token_algorithm(Algorithm)`
for explicit composition and tests. Its clone and issuer-override paths retain
the chosen algorithm. Existing callers that do not opt in retain RS256.
