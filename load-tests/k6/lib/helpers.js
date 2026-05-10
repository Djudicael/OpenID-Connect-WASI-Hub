//! Shared helpers for k6 load-test scripts.
//!
//! Provides:
//! - BASE_URL from env (default http://localhost:8080)
//! - THRESHOLDS matching the Phase-9 master checklist SLOs
//! - login()  — direct password login → access_token
//! - clientCredentialsToken() — client_credentials grant → access_token
//! - bearerHeaders() / apiKeyHeaders() — common header builders

import http from 'k6/http';
import { check } from 'k6';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Base URL of the OIDC Hub under test. Override with `BASE_URL` env var. */
export const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

/** SLO thresholds from the master checklist (Phase 9). */
export const THRESHOLDS = {
  discovery: {
    p99: ['p(99) < 50'],      // 9.1  — p99 < 50 ms
    error_rate: ['rate < 0.01'],
  },
  token: {
    p99: ['p(99) < 100'],     // 9.2  — p99 < 100 ms
    error_rate: ['rate < 0.01'],
  },
  userinfo: {
    p99: ['p(99) < 50'],      // 9.3  — p99 < 50 ms
    error_rate: ['rate < 0.01'],
  },
  apikey: {
    p99: ['p(99) < 20'],      // 9.4  — p99 < 20 ms
    error_rate: ['rate < 0.01'],
  },
};

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/**
 * Direct login via POST /oidc/login.
 *
 * Returns the `access_token` string on success, or an empty string on failure
 * (the failure is recorded as a failed check).
 *
 * @param {string} email     – user email (default: admin@localhost)
 * @param {string} password   – user password (default: admin123)
 * @param {string} clientId   – OAuth2 client_id (default: admin-ui)
 * @returns {string} access_token
 */
export function login(email = 'admin@localhost', password = 'admin123', clientId = 'admin-ui') {
  const res = http.post(
    `${BASE_URL}/oidc/login`,
    JSON.stringify({ email, password, client_id: clientId }),
    { headers: { 'Content-Type': 'application/json' } },
  );

  check(res, {
    'login status 200': (r) => r.status === 200,
  });

  try {
    return res.json('access_token') || '';
  } catch {
    return '';
  }
}

/**
 * Client-credentials token via POST /oidc/token.
 *
 * @param {string} clientId     – OAuth2 client_id
 * @param {string} clientSecret – OAuth2 client_secret
 * @returns {string} access_token
 */
export function clientCredentialsToken(clientId, clientSecret) {
  const res = http.post(`${BASE_URL}/oidc/token`, {
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
  });

  check(res, {
    'token status 200': (r) => r.status === 200,
  });

  try {
    return res.json('access_token') || '';
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Common HTTP option builders
// ---------------------------------------------------------------------------

/** Return headers for a Bearer-token request. */
export function bearerHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

/** Return headers for an API-key request (X-API-Key header). */
export function apiKeyHeaders(key) {
  return {
    'X-API-Key': key,
    'Content-Type': 'application/json',
  };
}
