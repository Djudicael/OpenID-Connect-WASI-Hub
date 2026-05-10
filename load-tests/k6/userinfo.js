//! UserInfo endpoint load test  (SLO 9.3)
//!
//! Target : 2 000 RPS, p99 < 50 ms
//!
//! Pre-requisites:
//!   - An admin user must exist (email / password).
//!   - Set ADMIN_EMAIL / ADMIN_PASSWORD env vars (or defaults are used).
//!
//! Run:
//!   k6 run load-tests/k6/userinfo.js
//!   k6 run -e BASE_URL=http://host:port load-tests/k6/userinfo.js

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, THRESHOLDS, login, bearerHeaders } from './lib/helpers.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ADMIN_EMAIL = __ENV.ADMIN_EMAIL || 'admin@localhost';
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD || 'admin123';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    userinfo: {
      executor: 'ramping-arrival-rate',
      exec: 'userinfo',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      maxVUs: 1000,
      stages: [
        { duration: '30s', target: 2000 },    // ramp to 2K RPS
        { duration: '2m', target: 2000 },    // hold 2K RPS
        { duration: '30s', target: 0 },       // ramp down
      ],
    },
  },
  thresholds: {
    http_req_duration: [{ threshold: THRESHOLDS.userinfo.p99[0], tags: { name: 'userinfo' } }],
    http_req_failed: [{ threshold: THRESHOLDS.userinfo.error_rate[0], tags: { name: 'userinfo' } }],
  },
};

// ---------------------------------------------------------------------------
// Setup — login once, share token across VUs
// ---------------------------------------------------------------------------

export function setup() {
  const token = login(ADMIN_EMAIL, ADMIN_PASSWORD);
  if (!token) {
    throw new Error('setup: login failed — check ADMIN_EMAIL / ADMIN_PASSWORD');
  }
  return { token };
}

// ---------------------------------------------------------------------------
// Test function
// ---------------------------------------------------------------------------

export default function (data) {
  userinfo(data.token);
}

function userinfo(token) {
  const res = http.get(`${BASE_URL}/oidc/userinfo`, {
    headers: bearerHeaders(token),
    tags: { name: 'userinfo' },
  });

  check(res, {
    'userinfo status 200': (r) => r.status === 200,
    'userinfo has sub': (r) => {
      try { return r.json('sub') !== undefined; } catch { return false; }
    },
  });
}
