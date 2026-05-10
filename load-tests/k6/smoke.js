//! Smoke test — 1 VU, 1 iteration, functional checks only.
//!
//! Verifies that every endpoint responds correctly without any
//! performance thresholds. Use this as a quick health-check
//! before running full load tests.
//!
//! Pre-requisites:
//!   - Admin user:          ADMIN_EMAIL / ADMIN_PASSWORD
//!   - Service client:      CLIENT_ID / CLIENT_SECRET
//!   - API key:             API_KEY / REALM_ID
//!
//! Run:
//!   k6 run load-tests/k6/smoke.js
//!   k6 run -e BASE_URL=http://host:port load-tests/k6/smoke.js

import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL,
  login,
  clientCredentialsToken,
  bearerHeaders,
  apiKeyHeaders,
} from './lib/helpers.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ADMIN_EMAIL = __ENV.ADMIN_EMAIL || 'admin@localhost';
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD || 'admin123';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-service-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-service-secret';
const API_KEY = __ENV.API_KEY || 'sk_test_admin_key_placeholder';
const REALM_ID = __ENV.REALM_ID || '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Options — minimal load, no performance thresholds
// ---------------------------------------------------------------------------

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    // No performance thresholds — only functional checks
    http_req_failed: ['rate < 0.5'], // Allow some failures for unseeded data
  },
};

// ---------------------------------------------------------------------------
// Test function
// ---------------------------------------------------------------------------

export default function () {
  // ---- Health endpoint ----
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health status 200': (r) => r.status === 200,
    'health has status ok': (r) => {
      try { return r.json('status') === 'ok'; } catch { return false; }
    },
  });

  // ---- Discovery endpoint ----
  const discoveryRes = http.get(`${BASE_URL}/.well-known/openid-configuration`);
  check(discoveryRes, {
    'discovery status 200': (r) => r.status === 200,
    'discovery has issuer': (r) => {
      try { return typeof r.json('issuer') === 'string'; } catch { return false; }
    },
    'discovery has token_endpoint': (r) => {
      try { return typeof r.json('token_endpoint') === 'string'; } catch { return false; }
    },
    'discovery has userinfo_endpoint': (r) => {
      try { return typeof r.json('userinfo_endpoint') === 'string'; } catch { return false; }
    },
  });

  // ---- Login endpoint ----
  const accessToken = login(ADMIN_EMAIL, ADMIN_PASSWORD);
  check(accessToken, {
    'login returned token': (t) => typeof t === 'string' && t.length > 0,
  });

  // ---- UserInfo endpoint ----
  if (accessToken) {
    const userinfoRes = http.get(`${BASE_URL}/oidc/userinfo`, {
      headers: bearerHeaders(accessToken),
    });
    check(userinfoRes, {
      'userinfo status 200': (r) => r.status === 200,
      'userinfo has sub': (r) => {
        try { return r.json('sub') !== undefined; } catch { return false; }
      },
    });
  }

  // ---- Token endpoint (client_credentials) ----
  const ccToken = clientCredentialsToken(CLIENT_ID, CLIENT_SECRET);
  check(ccToken, {
    'client_credentials returned token': (t) => typeof t === 'string' && t.length > 0,
  });

  // ---- API key endpoint ----
  const apikeyRes = http.get(`${BASE_URL}/api/keys?realm_id=${REALM_ID}`, {
    headers: apiKeyHeaders(API_KEY),
  });
  check(apikeyRes, {
    'apikey responds (2xx or 4xx)': (r) => r.status >= 200 && r.status < 500,
  });

  // ---- JWKS endpoint ----
  const jwksRes = http.get(`${BASE_URL}/oidc/jwks`);
  check(jwksRes, {
    'jwks status 200': (r) => r.status === 200,
  });
}
