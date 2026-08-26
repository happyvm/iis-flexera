# AGENTS.md

## Project objective

Build a lightweight PowerShell tool that measures **only the IIS workload of a Flexera Inventory Beacon** over a representative observation period (seven days by default).

Before making implementation decisions, read both normative documents:

1. [`SPECIFICATION.md`](SPECIFICATION.md) — functional behavior, data model, outputs and acceptance criteria.
2. [`FLEXERA-IIS-BASELINE.md`](FLEXERA-IIS-BASELINE.md) — Flexera-specific IIS requirements, recommendations and topology rules.

If these documents appear to conflict, preserve the read-only IIS-only scope and update the documentation before silently choosing a different behavior.

## Scope discipline

Do not expand the first version into a general Flexera monitor.

Unless explicitly requested, do **not** add:

- BeaconEngine performance monitoring,
- Oracle inventory monitoring,
- SQL/database monitoring,
- Flexera scheduled-task monitoring,
- Grafana/Prometheus/Centreon/Nagios integration,
- dashboards or web UI,
- automatic IIS tuning or remediation.

Focus on IIS, HTTP.sys, the relevant `w3wp.exe` worker process(es), IIS W3C logs and the resulting statistical report.

Reading narrowly-scoped Flexera local-web-server configuration metadata is allowed when required to discover or explain the IIS topology. Do not turn this into general BeaconEngine monitoring.

## Flexera baseline requirements

Implementation must account for Flexera's documented IIS behavior rather than assuming a generic IIS deployment.

In particular:

- use `ManageSoftRL` and `ManageSoftDL` as discovery hints,
- resolve their real site/AppPool topology instead of selecting an AppPool only by name,
- account for different authentication rules on standalone versus co-installed Beacon topologies,
- record effective authentication without collecting credentials,
- inventory the IIS prerequisites relevant to Flexera,
- check WebDAV state read-only,
- inspect Request Filtering for rules that could block known Flexera extensions such as `.osd`, `.npl`, `.nds` and `.ini`,
- record bindings/protocols/custom ports rather than assuming HTTP/80,
- validate that IIS logging is available for request analysis,
- treat missing Flexera prerequisites as reportable configuration evidence, not permission to remediate.

Do not invent or label CPU, RAM, request-rate, latency or queue thresholds as Flexera limits when Flexera has not published such thresholds.

## Implementation priorities

Work in this order unless a dependency requires otherwise:

1. Flexera/IIS preflight and topology discovery.
2. Flexera IIS configuration-baseline snapshot.
3. AppPool-to-worker-PID mapping.
4. Safe timed performance collection.
5. Stable CSV/JSON output.
6. W3C IIS log parser based on `#Fields:`.
7. P50/P95/P99 statistical analysis.
8. Markdown report generation.
9. Automated tests.

Reliable attribution and raw data are more important than visual presentation.

## Safety rules

The default monitoring path must be read-only.

Never automatically:

- restart IIS or the HTTP service,
- recycle an AppPool,
- change IIS queue lengths,
- modify Flexera configuration,
- modify authentication,
- enable or disable WebDAV,
- modify Request Filtering,
- change bindings or certificates,
- enable Failed Request Tracing,
- enable ETW tracing,
- collect dumps,
- change IIS logging fields,
- change the `DisableServerHeader` registry setting.

If an optional future feature requires a configuration change, it must be explicit and opt-in.

Never persist passwords, private keys or secret material. If AppPool account names are exported, support redaction/suppression.

## Compatibility

- Target Windows PowerShell 5.1 first.
- Avoid third-party runtime dependencies for v0.1.
- PowerShell 7 compatibility is desirable but secondary.
- Do not assume a fixed Flexera/IIS topology.
- Do not assume worker-process PIDs remain stable.
- Support overlapped recycle where multiple PIDs temporarily belong to one AppPool.
- Treat Flexera documentation as version-sensitive; do not assume every historical recommendation applies unchanged to every release.

## Coding expectations

- Use clear PowerShell functions with explicit inputs/outputs.
- Prefer structured APIs over fragile text parsing when practical.
- If `appcmd.exe` text must be parsed, isolate and test the parser.
- Preserve raw values required to reproduce statistical calculations.
- Treat missing optional performance counters as warnings, not fatal errors.
- Never fabricate unavailable measurements.
- Record collection errors in machine-readable output.
- Produce `configuration-baseline.json` as defined in `FLEXERA-IIS-BASELINE.md`.
- Keep vendor requirements/recommendations separate from project-specific heuristics in code and reports.

## Tests

At minimum test:

- W3C `#Fields:` parsing with multiple field orders,
- malformed/skipped W3C rows,
- status-code classification,
- percentile calculations,
- URI aggregation,
- AppPool/PID mapping logic,
- PID changes across recycle where integration testing is possible,
- standalone versus co-installed authentication-baseline logic,
- WebDAV detection,
- Request Filtering detection for known Flexera extensions,
- missing IIS prerequisite handling,
- custom HTTP/HTTPS binding discovery.

Sanitize all committed IIS log fixtures.

## Before declaring a task complete

Confirm that the change:

- remains inside the defined IIS-only scope,
- follows `FLEXERA-IIS-BASELINE.md`,
- does not modify production IIS/Flexera configuration by default,
- works without a fixed worker PID,
- handles missing data explicitly,
- does not mislabel project heuristics as Flexera recommendations,
- updates documentation when behavior or output schemas change,
- includes or updates tests for parsing/statistical/baseline logic.
