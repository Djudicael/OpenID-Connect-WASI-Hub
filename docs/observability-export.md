# Export internal realm metrics

Configure both `OIDC_OBSERVABILITY_REALM` and `OIDC_OBSERVABILITY_TOKEN` on the Hub.
The token must be a dedicated random 32-byte secret represented as 64 hexadecimal
characters. Keep it in your deployment secret manager, never in browser settings.
Without these settings the endpoint is disabled. Partial/invalid configuration
fails startup. Restart all instances when rotating the export token.

Poll `GET /api/v1/observability/realms/{realm}/metrics` with the export token in the
Bearer authorization header over HTTPS or a trusted loopback/private network.
Incorrect tokens, duplicate authorization headers and other realms are denied.
The response is not cacheable and contains only fixed aggregate gauges:

| Gauge | Meaning |
|---|---|
| `oidc.sessions.active` | Non-revoked, non-family-revoked sessions with unexpired access tokens |
| `oidc.sessions.created_5m` | Session rows created in the last five minutes, including rotations |
| `oidc.auth.audit_successes_5m` | Recorded `user.authenticated` audit events in the last five minutes |
| `oidc.auth.audit_failures_5m` | Recorded `LOGIN_FAILURE` audit events in the last five minutes |

These are gauges, not cumulative counters or a complete count of every login
mechanism. Existing best-effort audit writes determine coverage. Missing audit
events cannot be reconstructed. Cleanup changes the underlying retained state.
No actor/client identifiers, audit details, SQL or credentials are exported.
Queries run inside the Hub on native and WASI runtimes, with a two-second SQL
timeout and a three-second request deadline. Collection does not depend on
process-local state, filesystem access or a background task in the WASI instance.
An unavailable database returns 503; it must not be interpreted as zero activity.

The Observatory Rust collector supports this snapshot alongside HTTP-boundary
measurements and PostgreSQL JSON server logs. Configure one export realm per Hub
deployment; this endpoint does not grant organization-wide access to other realms.

## Optional request-local handler timing

Set `OIDC_OBSERVABILITY_TIMING=1` to add `x-oidc-handler-duration-ns` to backend
responses in native and WASI execution. Disabled by default. The middleware strips
an inbound copy and overwrites any handler-provided value with measured monotonic
integer nanoseconds. It measures middleware entry until a response object is
produced, excluding response-body transmission, host startup and proxy overhead.
It records no request paths, user/client identifiers, bodies or credentials.

This is a private hosting-adapter contract, not a public OIDC extension or a
deployment-wide in-memory counter. Restrict direct backend connections to trusted
peers. The gateway must strip the header before forwarding responses to browsers,
and must never trust a value supplied by a caller. Enabling timing alone does not
enable the realm-gauge endpoint or give access to another realm.

The local Observatory Rust proxy consumes valid timings and aggregates fixed-size
histogram buckets without changing Hub PostgreSQL state. Its collector exports
the cumulative snapshots through OTLP/HTTP to RustFS/DuckDB. The custom metric
`app.http.handler.duration` is a deployment-wide population, not a realm or route
metric. Missing/rejected timing does not become zero latency. Crashes, requests
bypassing the proxy and dropped responses are not observed; proxy restart resets
the population. No background task, local disk, telemetry database table or
outgoing telemetry request is added inside the WASI request component.

Production requires an equivalent reviewed hosting adapter; this local bridge
does not claim Wasm-Cloud-Platform telemetry integration is deployed.
