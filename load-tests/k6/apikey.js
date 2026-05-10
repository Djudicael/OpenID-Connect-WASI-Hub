//! API-key verification load test  (SLO 9.4)
//!
//! Target : 5 000 RPS, p99 < 20 ms
//!
//! Pre-requisites:
//!   - An API key with `admin` or `api_keys:read` scope must be seeded.
//!   - Set API_KEY and REALM_ID env vars (or defaults are used).
//!
//! Run:
//!   k6 run load-tests/k6/apikey.js
//!   k6 run -e BASE_URL=http://host:port -e API_KEY=sk_live_xxx -e REALM_ID=uuid load-tests/k6/apikey.js

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, THRESHOLDS, apiKeyHeaders } from './lib/helpers.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_KEY = __ENV.API_KEY || 'sk_test_admin_key_placeholder';
const REALM_ID = __ENV.REALM_ID || '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    apikey: {
      executor: 'ramping-arrival-rate',
      exec: 'apikey',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 100,
      maxVUs: 2000,
      stages: [
        { duration: '30s', target: 5000 },    // ramp to 5K RPS
        { duration: '2m', target: 5000 },    // hold 5K RPS
        { duration: '30s', target: 0 },       // ramp down
      ],
    },
  },
  thresholds: {
    http_req_duration: [{ threshold: THRESHOLDS.apikey.p99[0], tags: { name: 'apikey' } }],
    http_req_failed: [{ threshold: THRESHOLDS.apikey.error_rate[0], tags: { name: 'apikey' } }],
  },
};

// ---------------------------------------------------------------------------
// Test function
// ---------------------------------------------------------------------------

export default function () {
  apikey();
}

function apikey() {
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
