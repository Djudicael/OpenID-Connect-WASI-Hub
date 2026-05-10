//! Discovery endpoint load test  (SLO 9.1)
//!
//! Target : 10 000 RPS, p99 < 50 ms
//!
//! Run:
//!   k6 run load-tests/k6/discovery.js
//!   k6 run -e BASE_URL=http://host:port load-tests/k6/discovery.js

import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, THRESHOLDS } from './lib/helpers.js';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    discovery: {
      executor: 'ramping-arrival-rate',
      exec: 'discovery',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 200,
      maxVUs: 2000,
      stages: [
        { duration: '30s', target: 10000 },   // ramp to 10K RPS
        { duration: '2m', target: 10000 },   // hold 10K RPS
        { duration: '30s', target: 0 },        // ramp down
      ],
    },
  },
  thresholds: {
    http_req_duration: [{ threshold: THRESHOLDS.discovery.p99[0], tags: { name: 'discovery' } }],
    http_req_failed: [{ threshold: THRESHOLDS.discovery.error_rate[0], tags: { name: 'discovery' } }],
  },
};

// ---------------------------------------------------------------------------
// Test function
// ---------------------------------------------------------------------------

export default function () {
  discovery();
}

function discovery() {
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
