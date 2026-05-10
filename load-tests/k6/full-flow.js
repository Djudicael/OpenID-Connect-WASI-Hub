//! Full OIDC flow — 5-minute sustained load test  (SLO 9.9)
//!
//! Mix: 40% discovery, 30% token, 20% userinfo, 10% apikey
//! Overall error rate must be < 0.1%
//! All individual SLOs must be met simultaneously.
//!
//! Pre-requisites:
//!   - Admin user:          ADMIN_EMAIL / ADMIN_PASSWORD
//!   - Service client:      CLIENT_ID / CLIENT_SECRET
//!   - API key:             API_KEY / REALM_ID
//!
//! Run:
//!   k6 run load-tests/k6/full-flow.js
//!   k6 run -e BASE_URL=http://host:port \
//!          -e CLIENT_ID=test-svc -e CLIENT_SECRET=secret123 \
//!          -e API_KEY=sk_live_xxx -e REALM_ID=uuid \
//!          load-tests/k6/full-flow.js

import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL,
  THRESHOLDS,
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
// Options — 5-minute sustained load with mixed traffic
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // 40% discovery — target ~4 000 RPS
    discovery: {
      executor: 'ramping-arrival-rate',
      exec: 'discovery',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      maxVUs: 2000,
      stages: [
        { duration: '30s', target: 4000 },
        { duration: '3m30s', target: 4000 },
        { duration: '30s', target: 0 },
      ],
    },
    // 30% token — target ~3 000 RPS
    token: {
      executor: 'ramping-arrival-rate',
      exec: 'token',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 80,
      maxVUs: 1500,
      stages: [
        { duration: '30s', target: 3000 },
        { duration: '3m30s', target: 3000 },
        { duration: '30s', target: 0 },
      ],
    },
    // 20% userinfo — target ~2 000 RPS
    userinfo: {
      executor: 'ramping-arrival-rate',
      exec: 'userinfo',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 60,
      maxVUs: 1000,
      stages: [
        { duration: '30s', target: 2000 },
        { duration: '3m30s', target: 2000 },
        { duration: '30s', target: 0 },
      ],
    },
    // 10% apikey — target ~1 000 RPS
    apikey: {
      executor: 'ramping-arrival-rate',
      exec: 'apikey',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 40,
      maxVUs: 500,
      stages: [
        { duration: '30s', target: 1000 },
        { duration: '3m30s', target: 1000 },
        { duration: '30s', target: 0 },
      ],
    },
  },
  thresholds: {
    // Per-endpoint SLOs (tag-filtered)
    'http_req_duration{name:discovery}': ['p(99) < 50'],
    'http_req_duration{name:token}': ['p(99) < 100'],
    'http_req_duration{name:userinfo}': ['p(99) < 50'],
    'http_req_duration{name:apikey}': ['p(99) < 20'],
    // Overall error rate < 0.1%  (SLO 9.9)
    http_req_failed: ['rate < 0.001'],
  },
};

// ---------------------------------------------------------------------------
// Setup — obtain tokens once, share across VUs
// ---------------------------------------------------------------------------

export function setup() {
  const accessToken = login(ADMIN_EMAIL, ADMIN_PASSWORD);
  if (!accessToken) {
    throw new Error('setup: login failed — check ADMIN_EMAIL / ADMIN_PASSWORD');
  }

  const ccToken = clientCredentialsToken(CLIENT_ID, CLIENT_SECRET);
  // client_credentials failure is non-fatal for setup — the token scenario
  // will produce errors that count toward the error-rate threshold.

  return { accessToken, ccToken };
}

// ---------------------------------------------------------------------------
// Scenario functions
// ---------------------------------------------------------------------------

export function discovery() {
  const res = http.get(`${BASE_URL}/.well-known/openid-configuration`, {
    tags: { name: 'discovery' },
  });

  check(res, {
    'discovery status 200': (r) => r.status === 200,
    'discovery has issuer': (r) => {
      try { return r.json('issuer') !== undefined; } catch { return false; }
    },
  });
}

export function token() {
  const res = http.post(
    `${BASE_URL}/oidc/token`,
    {
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
    { tags: { name: 'token' } },
  );

  check(res, {
    'token status 200': (r) => r.status === 200,
    'token has access_token': (r) => {
      try { return typeof r.json('access_token') === 'string'; } catch { return false; }
    },
  });
}

export function userinfo(data) {
  const res = http.get(`${BASE_URL}/oidc/userinfo`, {
    headers: bearerHeaders(data.accessToken),
    tags: { name: 'userinfo' },
  });

  check(res, {
    'userinfo status 200': (r) => r.status === 200,
    'userinfo has sub': (r) => {
      try { return r.json('sub') !== undefined; } catch { return false; }
    },
  });
}

export function apikey() {
  const res = http.get(`${BASE_URL}/api/keys?realm_id=${REALM_ID}`, {
    headers: apiKeyHeaders(API_KEY),
    tags: { name: 'apikey' },
  });

  check(res, {
    'apikey status 200': (r) => r.status === 200,
    'apikey has items': (r) => {
      try { return Array.isArray(r.json('items')); } catch { return false; }
    },
  });
}
