# AGENTS.md

## Project objective

Build a lightweight PowerShell tool that measures **only the IIS workload of a Flexera Inventory Beacon** over a representative observation period (seven days by default).

Read [`SPECIFICATION.md`](SPECIFICATION.md) before making implementation decisions. It is the source of truth for scope, behavior, output and acceptance criteria.

## Scope discipline

Do not expand the first version into a general Flexera monitor.

Unless explicitly requested, do **not** add:

- BeaconEngine monitoring,
- Oracle inventory monitoring,
- SQL/database monitoring,
- Flexera scheduled-task monitoring,
- Grafana/Prometheus/Centreon/Nagios integration,
- dashboards or web UI,
- automatic IIS tuning.

Focus on IIS, HTTP.sys, the relevant `w3wp.exe` worker process(es), IIS W3C logs and the resulting statistical report.

## Implementation priorities

Work in this order unless a dependency requires otherwise:

1. IIS/Flexera topology discovery.
2. AppPool-to-worker-PID mapping.
3. Safe timed performance collection.
4. Stable CSV/JSON output.
5. W3C IIS log parser based on `#Fields:`.
6. P50/P95/P99 statistical analysis.
7. Markdown report generation.
8. Automated tests.

Reliable attribution and raw data are more important than visual presentation.

## Safety rules

The default monitoring path must be read-only.

Never automatically:

- restart IIS,
- recycle an AppPool,
- change IIS queue lengths,
- modify Flexera configuration,
- enable Failed Request Tracing,
- enable ETW tracing,
- collect dumps,
- change IIS logging fields.

If an optional future feature requires a configuration change, it must be explicit and opt-in.

## Compatibility

- Target Windows PowerShell 5.1 first.
- Avoid third-party runtime dependencies for v0.1.
- PowerShell 7 compatibility is desirable but secondary.
- Do not assume a fixed Flexera/IIS topology.
- Do not assume worker-process PIDs remain stable.
- Support overlapped recycle where multiple PIDs temporarily belong to one AppPool.

## Coding expectations

- Use clear PowerShell functions with explicit inputs/outputs.
- Prefer structured APIs over fragile text parsing when practical.
- If `appcmd.exe` text must be parsed, isolate and test the parser.
- Preserve raw values required to reproduce statistical calculations.
- Treat missing optional performance counters as warnings, not fatal errors.
- Never fabricate unavailable measurements.
- Record collection errors in machine-readable output.

## Tests

At minimum test:

- W3C `#Fields:` parsing with multiple field orders,
- malformed/skipped W3C rows,
- status-code classification,
- percentile calculations,
- URI aggregation,
- AppPool/PID mapping logic,
- PID changes across recycle where integration testing is possible.

Sanitize all committed IIS log fixtures.

## Before declaring a task complete

Confirm that the change:

- remains inside the defined IIS-only scope,
- does not modify production IIS/Flexera configuration by default,
- works without a fixed worker PID,
- handles missing data explicitly,
- updates documentation when behavior or output schemas change,
- includes or updates tests for parsing/statistical logic.
