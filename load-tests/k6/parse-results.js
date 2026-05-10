#!/usr/bin/env node
// ---------------------------------------------------------------------------
// parse-results.js — Parse k6 JSON output and compare against SLO thresholds
//
// Reads one or more k6 JSON output files, extracts key metrics (p50, p95, p99,
// error rate, RPS) per tagged endpoint, and prints a pass/fail summary table.
//
// Usage:
//   node load-tests/k6/parse-results.js results/*.json
//   node load-tests/k6/parse-results.js results/discovery-20250115-143022.json
//   node load-tests/k6/parse-results.js --dir results/
//
// Output:
//   - Console table with per-endpoint metrics and SLO pass/fail
//   - Exit code 0 if all SLOs met, 1 if any SLO violated
// ---------------------------------------------------------------------------

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// SLO thresholds (must match lib/helpers.js and the master checklist)
// ---------------------------------------------------------------------------
const SLO_THRESHOLDS = {
  discovery: { p99: 50, errorRate: 0.01, targetRPS: 10000 },
  token: { p99: 100, errorRate: 0.01, targetRPS: 1000 },
  userinfo: { p99: 50, errorRate: 0.01, targetRPS: 2000 },
  apikey: { p99: 20, errorRate: 0.01, targetRPS: 5000 },
};

// Overall SLO 9.9 threshold
const OVERALL_ERROR_RATE_THRESHOLD = 0.001; // 0.1%

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);

if (args.length === 0) {
  console.error('Usage: node parse-results.js <file1.json> [file2.json ...]');
  console.error('       node parse-results.js --dir <directory>');
  process.exit(2);
}

let files = [];

if (args[0] === '--dir') {
  const dir = args[1] || '.';
  if (!fs.existsSync(dir)) {
    console.error(`Directory not found: ${dir}`);
    process.exit(2);
  }
  files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .map(f => path.join(dir, f));
} else {
  files = args.filter(a => !a.startsWith('--'));
}

if (files.length === 0) {
  console.error('No JSON files found to parse.');
  process.exit(2);
}

// ---------------------------------------------------------------------------
// k6 JSON line format
// ---------------------------------------------------------------------------
// Each line is a JSON object with at least: type, metric, data
// Relevant types: Point (metric data point)
// Relevant metrics: http_req_duration, http_req_failed, http_reqs
// Tags include: name (endpoint tag), error_code, etc.

/**
 * Parse a single k6 JSON output file.
 * Returns an object mapping endpoint names to metric arrays.
 */
function parseK6Json(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim());

  // Collect raw data points per metric per endpoint
  const data = {
    http_req_duration: {},  // endpoint -> [values in ms]
    http_req_failed: {},    // endpoint -> [0 or 1]
    http_reqs: {},          // endpoint -> count
  };

  let testRunStart = null;
  let testRunEnd = null;

  for (const line of lines) {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      // Skip malformed lines
      continue;
    }

    if (entry.type !== 'Point') continue;

    const metric = entry.metric;
    const tags = entry.data?.tags || {};
    const value = entry.data?.value;
    const timestamp = entry.data?.time;

    // Track time range
    if (timestamp) {
      const ts = new Date(timestamp).getTime();
      if (testRunStart === null || ts < testRunStart) testRunStart = ts;
      if (testRunEnd === null || ts > testRunEnd) testRunEnd = ts;
    }

    // Determine endpoint name from tags
    const endpoint = tags.name || tags.scenario || 'unknown';

    if (metric === 'http_req_duration') {
      if (!data.http_req_duration[endpoint]) data.http_req_duration[endpoint] = [];
      data.http_req_duration[endpoint].push(value);
    } else if (metric === 'http_req_failed') {
      if (!data.http_req_failed[endpoint]) data.http_req_failed[endpoint] = [];
      data.http_req_failed[endpoint].push(value);
    } else if (metric === 'http_reqs') {
      if (!data.http_reqs[endpoint]) data.http_reqs[endpoint] = 0;
      data.http_reqs[endpoint]++;
    }
  }

  // Calculate duration in seconds
  const durationSec = testRunStart && testRunEnd
    ? (testRunEnd - testRunStart) / 1000
    : 0;

  return { data, durationSec };
}

/**
 * Calculate a percentile from a sorted array.
 */
function percentile(sortedArr, p) {
  if (sortedArr.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sortedArr.length) - 1;
  return sortedArr[Math.max(0, idx)];
}

/**
 * Compute metrics for an endpoint from raw data.
 */
function computeEndpointMetrics(durationData, failedData, reqsCount, durationSec) {
  const durations = (durationData || []).sort((a, b) => a - b);
  const failures = failedData || [];
  const totalReqs = reqsCount || 0;

  const p50 = percentile(durations, 50);
  const p95 = percentile(durations, 95);
  const p99 = percentile(durations, 99);
  const avg = durations.length > 0
    ? durations.reduce((s, v) => s + v, 0) / durations.length
    : 0;
  const errorCount = failures.filter(v => v === 1).length;
  const errorRate = failures.length > 0 ? errorCount / failures.length : 0;
  const rps = durationSec > 0 ? totalReqs / durationSec : 0;

  return { p50, p95, p99, avg, errorRate, errorCount, totalReqs, rps };
}

// ---------------------------------------------------------------------------
// Process all files
// ---------------------------------------------------------------------------
const allResults = [];
let anySLOFailed = false;

for (const file of files) {
  const basename = path.basename(file, '.json');
  // Extract test name from filename (e.g., "discovery-20250115-143022" -> "discovery")
  const testName = basename.replace(/-\d{8}-\d{6}$/, '');

  let parsed;
  try {
    parsed = parseK6Json(file);
  } catch (err) {
    console.error(`Error parsing ${file}: ${err.message}`);
    continue;
  }

  const { data, durationSec } = parsed;

  // For each endpoint found in the data
  const endpoints = Object.keys(data.http_req_duration);

  for (const endpoint of endpoints) {
    const metrics = computeEndpointMetrics(
      data.http_req_duration[endpoint],
      data.http_req_failed[endpoint],
      data.http_reqs[endpoint] || 0,
      durationSec,
    );

    const slo = SLO_THRESHOLDS[endpoint] || null;

    let p99Pass = null;
    let errorRatePass = null;
    let rpsPass = null;

    if (slo) {
      p99Pass = metrics.p99 < slo.p99;
      errorRatePass = metrics.errorRate < slo.errorRate;
      rpsPass = slo.targetRPS ? metrics.rps >= slo.targetRPS * 0.9 : null; // 90% of target as floor
      if (!p99Pass || !errorRatePass) anySLOFailed = true;
    }

    allResults.push({
      file: basename,
      testName,
      endpoint,
      slo: slo ? `9.${Object.keys(SLO_THRESHOLDS).indexOf(endpoint) + 1}` : '—',
      ...metrics,
      p99Threshold: slo?.p99 || '—',
      errorRateThreshold: slo?.errorRate || '—',
      targetRPS: slo?.targetRPS || '—',
      p99Pass,
      errorRatePass,
      rpsPass,
    });
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// Sort: discovery, token, userinfo, apikey first, then others
const endpointOrder = ['discovery', 'token', 'userinfo', 'apikey'];
allResults.sort((a, b) => {
  const ai = endpointOrder.indexOf(a.endpoint);
  const bi = endpointOrder.indexOf(b.endpoint);
  const ao = ai === -1 ? 999 : ai;
  const bo = bi === -1 ? 999 : bi;
  if (ao !== bo) return ao - bo;
  return a.file.localeCompare(b.file);
});

// Print header
console.log('');
console.log('╔══════════════════════════════════════════════════════════════════════════════════════════════════╗');
console.log('║                     OIDC Hub — k6 Load Test Results vs SLO Thresholds                        ║');
console.log('╚══════════════════════════════════════════════════════════════════════════════════════════════════╝');
console.log('');

// Table header
const hdr = [
  'SLO'.padEnd(5),
  'Endpoint'.padEnd(12),
  'p50 (ms)'.padEnd(10),
  'p95 (ms)'.padEnd(10),
  'p99 (ms)'.padEnd(10),
  'p99 Thr'.padEnd(8),
  'p99?'.padEnd(5),
  'Err Rate'.padEnd(10),
  'Err Thr'.padEnd(8),
  'Err?'.padEnd(5),
  'RPS'.padEnd(10),
  'RPS Thr'.padEnd(9),
  'RPS?'.padEnd(5),
].join(' │ ');

const sep = '─'.repeat(hdr.length + 2);

console.log(`  ${hdr}`);
console.log(`  ${sep}`);

for (const r of allResults) {
  const p99Str = r.p99.toFixed(1).padEnd(10);
  const p99ThrStr = typeof r.p99Threshold === 'number' ? `<${r.p99Threshold}`.padEnd(8) : String(r.p99Threshold).padEnd(8);
  const p99Icon = r.p99Pass === null ? '—'.padEnd(5) : (r.p99Pass ? '✅'.padEnd(3) : '❌'.padEnd(3)).padEnd(5);

  const errStr = (r.errorRate * 100).toFixed(3).padEnd(10);
  const errThrStr = typeof r.errorRateThreshold === 'number' ? `<${(r.errorRateThreshold * 100).toFixed(1)}%`.padEnd(8) : String(r.errorRateThreshold).padEnd(8);
  const errIcon = r.errorRatePass === null ? '—'.padEnd(5) : (r.errorRatePass ? '✅'.padEnd(3) : '❌'.padEnd(3)).padEnd(5);

  const rpsStr = r.rps.toFixed(0).padEnd(10);
  const rpsThrStr = typeof r.targetRPS === 'number' ? `≥${r.targetRPS}`.padEnd(9) : String(r.targetRPS).padEnd(9);
  const rpsIcon = r.rpsPass === null ? '—'.padEnd(5) : (r.rpsPass ? '✅'.padEnd(3) : '❌'.padEnd(3)).padEnd(5);

  const row = [
    r.slo.padEnd(5),
    r.endpoint.padEnd(12),
    r.p50.toFixed(1).padEnd(10),
    r.p95.toFixed(1).padEnd(10),
    p99Str,
    p99ThrStr,
    p99Icon,
    errStr,
    errThrStr,
    errIcon,
    rpsStr,
    rpsThrStr,
    rpsIcon,
  ].join(' │ ');

  console.log(`  ${row}`);
}

console.log(`  ${sep}`);

// Overall summary
const totalReqs = allResults.reduce((s, r) => s + r.totalReqs, 0);
const totalErrors = allResults.reduce((s, r) => s + r.errorCount, 0);
const overallErrorRate = totalReqs > 0 ? totalErrors / totalReqs : 0;
const overallErrorPass = overallErrorRate < OVERALL_ERROR_RATE_THRESHOLD;

console.log('');
console.log(`  Total Requests:  ${totalReqs.toLocaleString()}`);
console.log(`  Total Errors:    ${totalErrors.toLocaleString()}`);
console.log(`  Overall Error:   ${(overallErrorRate * 100).toFixed(3)}%  (threshold: <${(OVERALL_ERROR_RATE_THRESHOLD * 100).toFixed(1)}%)  ${overallErrorPass ? '✅' : '❌'}`);
console.log('');

// SLO 9.9 check
if (!overallErrorPass) anySLOFailed = true;

// Final verdict
const sloEndpoints = allResults.filter(r => r.slo !== '—');
const allP99Pass = sloEndpoints.every(r => r.p99Pass !== false);
const allErrPass = sloEndpoints.every(r => r.errorRatePass !== false);

console.log('  ┌─────────────────────────────────┐');
if (!anySLOFailed && allP99Pass && allErrPass && overallErrorPass) {
  console.log('  │  🟢  ALL SLOs MET — PASS        │');
} else {
  console.log('  │  🔴  SLO VIOLATION — FAIL       │');
}
console.log('  └─────────────────────────────────┘');
console.log('');

// JSON output for CI integration
if (args.includes('--json')) {
  const jsonOutput = {
    timestamp: new Date().toISOString(),
    overallErrorRate,
    overallErrorPass,
    anySLOFailed,
    results: allResults.map(r => ({
      endpoint: r.endpoint,
      slo: r.slo,
      p50: r.p50,
      p95: r.p95,
      p99: r.p99,
      p99Threshold: r.p99Threshold,
      p99Pass: r.p99Pass,
      errorRate: r.errorRate,
      errorRateThreshold: r.errorRateThreshold,
      errorRatePass: r.errorRatePass,
      rps: r.rps,
      targetRPS: r.targetRPS,
      rpsPass: r.rpsPass,
      totalReqs: r.totalReqs,
    })),
  };
  const jsonPath = path.join(path.dirname(files[0]), `summary-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(jsonOutput, null, 2));
  console.log(`  📄 JSON summary written to: ${jsonPath}`);
  console.log('');
}

process.exit(anySLOFailed ? 1 : 0);
