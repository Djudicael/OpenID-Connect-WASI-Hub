//! Token endpoint load test  (SLO 9.2)
//!
//! Target : 1 000 RPS, p99 < 100 ms
//!
//! Pre-requisites:
//!   - A confidential client with client_credentials grant must exist.
//!   - Set CLIENT_ID and CLIENT_SECRET env vars (or defaults are used).
//!
//! Run:
//!   k6 run load-tests/k6/token.js
//!   k6 run -e BASE_URL=http://host:port -e CLIENT_ID=test-svc -e CLIENT_SECRET=secret123 load-tests/k6/token.js

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, THRESHOLDS } from './lib/helpers.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CLIENT_ID = __ENV.CLIENT_ID || 'test-service-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-service-secret';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    token: {
      executor: 'ramping-arrival-rate',
      exec: 'token',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: '30s', target: 1000 },    // ramp to 1K RPS
        { duration: '2m', target: 1000 },    // hold 1K RPS
        { duration: '30s', target: 0 },       // ramp down
      ],
    },
  },
  thresholds: {
    http_req_duration: [{ threshold: THRESHOLDS.token.p99[0], tags: { name: 'token' } }],
    http_req_failed: [{ threshold: THRESHOLDS.token.error_rate[0], tags: { name: 'token' } }],
  },
};

// ---------------------------------------------------------------------------
// Test function
// ---------------------------------------------------------------------------

export default function () {
  token();
}

function token() {
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
    'token type Bearer': (r) => {
      try { return r.json('token_type') === 'Bearer'; } catch { return false; }
    },
  });
}
