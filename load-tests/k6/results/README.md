# Load Test Results

This directory stores k6 JSON output files from load test runs.

## File Naming Convention

```
<test-name>-<YYYYMMDD>-<HHMMSS>.json
```

Example: `discovery-20250115-143022.json`

## SLO Thresholds (Phase 9 Master Checklist)

These are the **hard thresholds** that must be met for a passing run.

| SLO  | Endpoint / Metric           | Target                              | Threshold              |
|------|-----------------------------|-------------------------------------|------------------------|
| 9.1  | Discovery endpoint p99      | < 50 ms @ 10 000 RPS               | `p(99) < 50`          |
| 9.2  | Token endpoint p99         | < 100 ms @ 1 000 RPS               | `p(99) < 100`         |
| 9.3  | UserInfo endpoint p99       | < 50 ms @ 2 000 RPS                | `p(99) < 50`          |
| 9.4  | API key verification p99   | < 20 ms @ 5 000 RPS                | `p(99) < 20`          |
| 9.5  | Memory stable under load    | No growth after 5 min               | Manual check          |
| 9.6  | PostgreSQL pool not exhausted | max_connections never hit at 2×   | Manual check          |
| 9.7  | WASM artifact size          | < 20 MB                             | Manual check          |
| 9.8  | WASM startup time           | < 2 s (time to first health OK)     | Manual check          |
| 9.9  | 5-minute load test          | All SLOs met; error rate < 0.1%     | `rate < 0.001`        |

## Baseline Results Template

Record baseline results from the first successful load test run below. These
serve as the reference point for future regressions.

### Run Metadata

| Field           | Value |
|-----------------|-------|
| **Date**        | _YYYY-MM-DD_ |
| **Git Commit**  | _short hash_ |
| **Target**      | _native / wasm32-wasip2_ |
| **Runtime**     | _wasmtime X.Y.Z / native tokio_ |
| **Host OS**     | _e.g. Ubuntu 22.04_ |
| **CPU**         | _e.g. AMD EPYC 7763 8 vCPU_ |
| **RAM**         | _e.g. 32 GB_ |
| **PostgreSQL**  | _e.g. PG 15, max_connections=200_ |
| **k6 Version**  | _e.g. v0.47.0_ |
| **BASE_URL**    | _http://localhost:8080_ |

### Per-Endpoint Baselines

| SLO  | Endpoint   | Target RPS | Achieved RPS | p50 (ms) | p95 (ms) | p99 (ms) | Error Rate | Pass? |
|------|------------|-----------|-------------|----------|----------|----------|------------|-------|
| 9.1  | Discovery  | 10 000    | _—_         | _—_      | _—_      | _< 50_   | _< 1%_     | ☐     |
| 9.2  | Token      | 1 000     | _—_         | _—_      | _—_      | _< 100_  | _< 1%_     | ☐     |
| 9.3  | UserInfo   | 2 000     | _—_         | _—_      | _—_      | _< 50_   | _< 1%_     | ☐     |
| 9.4  | API Key    | 5 000     | _—_         | _—_      | _—_      | _< 20_   | _< 1%_     | ☐     |

### Full-Flow Baseline (SLO 9.9)

| Metric                    | Target   | Measured | Pass? |
|---------------------------|----------|----------|-------|
| Overall error rate        | < 0.1%   | _—_      | ☐     |
| Discovery p99             | < 50 ms  | _—_      | ☐     |
| Token p99                 | < 100 ms | _—_      | ☐     |
| UserInfo p99              | < 50 ms  | _—_      | ☐     |
| API Key p99              | < 20 ms  | _—_      | ☐     |
| Total RPS (sum)           | ≥ 10 000 | _—_      | ☐     |

### Infrastructure Checks (Manual)

| SLO  | Check                      | Result | Pass? |
|------|----------------------------|--------|-------|
| 9.5  | Memory stable after 5 min  | _—_ MB | ☐     |
| 9.6  | PG pool not exhausted      | _—_    | ☐     |
| 9.7  | WASM artifact size         | _—_ MB | ☐     |
| 9.8  | WASM startup time          | _—_ s  | ☐     |

## Parsing Results

Use the Node.js parser to extract metrics from JSON output files:

```bash
node load-tests/k6/parse-results.js results/*.json
```

This will print a pass/fail summary table comparing all metrics against the
SLO thresholds above.

## .gitignore

JSON result files can be large. Add them to `.gitignore` if you don't want them
tracked:

```gitignore
# Load test results (large JSON files)
load-tests/k6/results/*.json
```
