# Proxy cookbook for the two-WASI deployment

This document provides copy-ready reverse-proxy examples for the browser-facing deployment where:

- `oidc_admin_wasi.wasm` serves the admin SPA
- `openid_connect_wasi.wasm` serves the OIDC/API/backend routes
- one public origin sits in front of both

## Assumed upstreams

Adjust these to your environment:

- public host: `auth.example.com`
- frontend WASI upstream: `127.0.0.1:3001`
- backend WASI upstream: `127.0.0.1:8080`

## Routing model

### Send to backend WASI

- `/api/*`
- `/oidc/*`
- `/.well-known/*`
- `/health`
- `/health/*`
- `/realms/{realm}/login`
- `/realms/{realm}/protocol/*`
- `/realms/{realm}/.well-known/*`

### Send to frontend WASI

- `/`
- `/admin`
- `/admin/*`
- `/js/*`
- `/style/*`
- SPA routes like `/users`, `/clients`, `/roles`, `/groups`, `/realms`, `/realms/{id}`
- any browser-facing route not matched by the backend rules above

## Important routing nuance

Do **not** route every `/realms/*` path to the backend.

Examples:

- `/realms/master/login` -> backend WASI
- `/realms/master/protocol/openid-connect/token` -> backend WASI
- `/realms/master/.well-known/openid-configuration` -> backend WASI
- `/realms/123` -> frontend WASI (admin SPA page)

The backend rule for realm paths should only match:

- `/realms/<realm>/login`
- `/realms/<realm>/protocol/...`
- `/realms/<realm>/.well-known/...`

---

## Recommended backend env behind the proxy

For the backend WASI app, prefer something like:

```text
OIDC_ISSUER=https://auth.example.com
OIDC_RATE_LIMIT_MODE=proxy
```

If you trust the first-hop proxy and want forwarded headers to be honored, also review:

```text
OIDC_TRUST_PROXY_HEADERS=true
```

Only enable that when the upstream proxy strips and rebuilds forwarded headers itself.

---

## Nginx example

```nginx
server {
    listen 80;
    server_name auth.example.com;

    # TLS termination can be added here or handled by another layer.

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_http_version 1.1;

    # Backend: top-level protocol/API routes
    location ^~ /api/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location ^~ /oidc/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location ^~ /.well-known/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location ^~ /health {
        proxy_pass http://127.0.0.1:8080;
    }

    # Backend: realm protocol routes
    location ~ ^/realms/[^/]+/login$ {
        proxy_pass http://127.0.0.1:8080;
    }

    location ~ ^/realms/[^/]+/protocol/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location ~ ^/realms/[^/]+/\.well-known/ {
        proxy_pass http://127.0.0.1:8080;
    }

    # Frontend WASI: everything else
    location / {
        proxy_pass http://127.0.0.1:3001;
    }
}
```

---

## Caddy example

```caddy
auth.example.com {
    @backend_api path /api/* /oidc/* /.well-known/* /health /health/*
    reverse_proxy @backend_api 127.0.0.1:8080

    @realm_login path_regexp realm_login ^/realms/[^/]+/login$
    reverse_proxy @realm_login 127.0.0.1:8080

    @realm_protocol path_regexp realm_protocol ^/realms/[^/]+/protocol/.+
    reverse_proxy @realm_protocol 127.0.0.1:8080

    @realm_well_known path_regexp realm_well_known ^/realms/[^/]+/\.well-known/.+
    reverse_proxy @realm_well_known 127.0.0.1:8080

    # Frontend WASI for everything else
    reverse_proxy 127.0.0.1:3001
}
```

---

## Traefik dynamic-file example

```yaml
http:
  routers:
    oidc-backend-api:
      rule: >
        Host(`auth.example.com`) &&
        (
          PathPrefix(`/api/`) ||
          PathPrefix(`/oidc/`) ||
          PathPrefix(`/.well-known/`) ||
          PathPrefix(`/health`)
        )
      service: oidc-backend
      priority: 200

    oidc-backend-realms-login:
      rule: Host(`auth.example.com`) && PathRegexp(`^/realms/[^/]+/login$`)
      service: oidc-backend
      priority: 210

    oidc-backend-realms-protocol:
      rule: Host(`auth.example.com`) && PathRegexp(`^/realms/[^/]+/protocol/.*`)
      service: oidc-backend
      priority: 210

    oidc-backend-realms-wellknown:
      rule: Host(`auth.example.com`) && PathRegexp(`^/realms/[^/]+/\\.well-known/.*`)
      service: oidc-backend
      priority: 210

    oidc-frontend:
      rule: Host(`auth.example.com`)
      service: oidc-frontend
      priority: 10

  services:
    oidc-backend:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"

    oidc-frontend:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:3001"
```

Higher priority on backend routes is important so the catch-all frontend router does not win.

---

## HAProxy example

```haproxy
frontend oidc_front
    bind *:80
    mode http

    option forwardfor
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Host %[req.hdr(host)]

    acl is_api path_beg /api/ /oidc/ /.well-known/ /health
    acl is_realm_login path_reg ^/realms/[^/]+/login$
    acl is_realm_protocol path_reg ^/realms/[^/]+/protocol/.*
    acl is_realm_well_known path_reg ^/realms/[^/]+/\.well-known/.*

    use_backend oidc_backend if is_api
    use_backend oidc_backend if is_realm_login
    use_backend oidc_backend if is_realm_protocol
    use_backend oidc_backend if is_realm_well_known

    default_backend oidc_frontend

backend oidc_backend
    mode http
    server backend1 127.0.0.1:8080

backend oidc_frontend
    mode http
    server frontend1 127.0.0.1:3001
```

## HAProxy TLS termination example (production-oriented baseline)

This is a stronger starting point for production-style deployments with:

- HTTP -> HTTPS redirect
- TLS termination at HAProxy
- forwarded headers for the backend
- host filtering
- health checks
- connection timeouts
- HSTS

Replace the certificate path and hostnames with your real values.

```haproxy
global
    log stdout format raw local0 info
    maxconn 50000
    tune.ssl.default-dh-param 2048

    # Reasonable modern TLS defaults; tune to your platform/compliance needs.
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option forwardfor
    retries 3

    timeout http-request 10s
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    timeout http-keep-alive 15s

frontend oidc_http
    bind :80
    mode http
    http-request redirect scheme https code 301

frontend oidc_https
    bind :443 ssl crt /etc/haproxy/certs/auth.example.com.pem alpn h2,http/1.1
    mode http

    # Only serve the intended hostname.
    acl host_auth hdr(host) -i auth.example.com
    http-request deny deny_status 421 unless host_auth

    # Forward the original browser-facing origin to the WASI apps.
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host %[req.hdr(host)]
    http-request set-header X-Forwarded-Port 443

    # Security headers at the edge. Avoid overriding CSP here unless you intend to.
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header Referrer-Policy strict-origin-when-cross-origin

    acl is_api path_beg /api/ /oidc/ /.well-known/ /health
    acl is_realm_login path_reg ^/realms/[^/]+/login$
    acl is_realm_protocol path_reg ^/realms/[^/]+/protocol/.*
    acl is_realm_well_known path_reg ^/realms/[^/]+/\.well-known/.*

    use_backend oidc_backend if is_api
    use_backend oidc_backend if is_realm_login
    use_backend oidc_backend if is_realm_protocol
    use_backend oidc_backend if is_realm_well_known

    default_backend oidc_frontend

backend oidc_backend
    mode http
    balance roundrobin

    option httpchk GET /health
    http-check expect status 200

    server backend1 127.0.0.1:8080 check inter 5s fall 3 rise 2
    # Add more backend WASI instances like:
    # server backend2 127.0.0.1:8081 check inter 5s fall 3 rise 2

backend oidc_frontend
    mode http
    balance roundrobin

    option httpchk GET /
    http-check expect status 200

    server frontend1 127.0.0.1:3001 check inter 5s fall 3 rise 2
    # Add more frontend WASI instances like:
    # server frontend2 127.0.0.1:3002 check inter 5s fall 3 rise 2
```

### HAProxy production notes

- Set the backend WASI issuer to the public origin, for example:
  - `OIDC_ISSUER=https://auth.example.com`
- If the backend is supposed to honor proxy headers, enable that only behind a trusted first hop:
  - `OIDC_TRUST_PROXY_HEADERS=true`
- If you scale out, keep the proxy routing logic identical for every instance group.
- Prefer doing rate limiting at the edge or load balancer layer; the app-local limiter is only a per-instance safety net unless you intentionally rely on it.
- The frontend WASI should be treated as an HTTP upstream, not as a static directory on disk; its assets are embedded into `oidc_admin_wasi.wasm`.

---

## Generic routing spec

If you have not chosen a proxy yet, this is the minimum rule set to preserve:

```text
backend:
  - /api/*
  - /oidc/*
  - /.well-known/*
  - /health*
  - /realms/{realm}/login
  - /realms/{realm}/protocol/*
  - /realms/{realm}/.well-known/*

frontend:
  - /
  - /admin*
  - /js/*
  - /style/*
  - /users*
  - /roles*
  - /groups*
  - /clients*
  - /realms
  - /realms/{id}
  - SPA fallback: everything else not matched above
```

## Operational note

The frontend WASI does not serve files from disk at runtime. The admin HTML/CSS/JS are embedded into `oidc_admin_wasi.wasm` at build time. The reverse proxy should therefore treat the frontend WASI as a normal HTTP upstream, not as a filesystem/static-file root.
