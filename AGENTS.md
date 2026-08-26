# AGENTS.md

## Project objective

Build a lightweight PowerShell tool that measures **only the IIS workload of a Flexera Inventory Beacon** over a representative observation period (seven days by default), and performs a read-only IIS security/configuration assessment that remains compatible with Flexera requirements.

Before making implementation decisions, read all normative documents:

1. [`SPECIFICATION.md`](SPECIFICATION.md) — functional behavior, data model, outputs and acceptance criteria.
2. [`FLEXERA-IIS-BASELINE.md`](FLEXERA-IIS-BASELINE.md) — Flexera-specific IIS requirements, recommendations and topology rules.
3. [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) — Microsoft IIS vs Flexera security comparison, control catalogue and compatibility-exception rules.

For security decisions, `SECURITY-AUDIT.md` is the source of truth. Do not apply generic IIS hardening blindly when Flexera documents a requirement or compatibility constraint.

## Scope discipline

Do not expand the first version into a general Flexera monitor.

Unless explicitly requested, do **not** add:

- BeaconEngine performance monitoring,
- Oracle inventory monitoring,
- SQL/database monitoring,
- Flexera scheduled-task monitoring,
- Grafana/Prometheus/Centreon/Nagios integration,
- dashboards or web UI,
- automatic IIS tuning,
- automatic security remediation.

Focus on IIS, HTTP.sys, the relevant `w3wp.exe` worker process(es), IIS W3C logs, configuration/security posture and the resulting reports.

Reading narrowly-scoped Flexera local-web-server/security metadata is allowed when required to discover or explain IIS. Never collect secrets and do not turn this into general BeaconEngine monitoring.

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
- for IIS-based Beacon-agent communications, treat ports 80/443 as the current documented standard Flexera ports rather than assuming arbitrary custom IIS ports are equivalent,
- validate that IIS logging is available for request analysis,
- treat missing Flexera prerequisites as reportable configuration evidence, not permission to remediate.

Do not invent or label CPU, RAM, request-rate, latency or queue thresholds as Flexera limits when Flexera has not published such thresholds.

## Security assessment model

The audit is a three-way comparison:

```text
Observed configuration
vs Microsoft IIS guidance
vs Flexera guidance
```

Then derive an **effective recommendation** that remains compatible with the deployed Flexera design.

Required statuses:

```text
PASS
FAIL
WARNING
INFO
NOT_APPLICABLE
UNKNOWN
FLEXERA_EXCEPTION
CONFLICT
```

Do not generate a single percentage security score in v0.1.

Distinguish vendor evidence explicitly:

```text
FLEXERA_REQUIRED
FLEXERA_RECOMMENDED
FLEXERA_OPTIONAL_SECURITY
FLEXERA_COMPATIBILITY
```

Important rules:

- Prefer HTTPS for Beacon-agent communication.
- Basic Authentication must not be considered secure over unencrypted HTTP.
- Flexera prefers anonymous IIS authentication where possible for agent/failover behavior; do not flag anonymous access as a generic failure without evaluating this product-specific requirement.
- Mutual TLS is a supported optional enhanced-security design, not the default mandatory baseline.
- WebDAV must be disabled on relevant Flexera IIS paths.
- Request Filtering should improve security without blocking Flexera-required payload extensions.
- Distinguish Windows role-service/module installation from the effective site/application/path setting.
- Prefer low-privilege isolated AppPool identities unless Flexera documents otherwise.
- Never export passwords, private keys, authorization headers, cookies or sensitive query-string secrets.

## Implementation priorities

Work in this order unless a dependency requires otherwise:

1. Flexera/IIS preflight and topology discovery.
2. Flexera IIS configuration-baseline snapshot.
3. Read-only security configuration discovery.
4. AppPool-to-worker-PID mapping.
5. Safe timed performance collection.
6. Stable CSV/JSON output.
7. W3C IIS log parser based on `#Fields:`.
8. P50/P95/P99 statistical analysis.
9. Microsoft/Flexera security assessment.
10. Markdown report generation.
11. Automated tests.

Reliable attribution, raw data and correct vendor interpretation are more important than visual presentation.

## Safety rules

The default monitoring and audit path must be read-only.

Never automatically:

- restart IIS or the HTTP service,
- recycle an AppPool,
- change IIS queue lengths,
- modify Flexera configuration,
- modify authentication,
- enable or disable WebDAV,
- modify Request Filtering,
- change bindings or certificates,
- change TLS protocol configuration,
- enable HSTS,
- add/remove IIS role services,
- change AppPool identities,
- change Flexera registry security preferences,
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
- Record detected Windows Server, IIS and Flexera Beacon versions when practical.

## Coding expectations

- Use clear PowerShell functions with explicit inputs/outputs.
- Prefer structured APIs over fragile text parsing when practical.
- If `appcmd.exe` text must be parsed, isolate and test the parser.
- Preserve raw values required to reproduce statistical calculations.
- Treat missing optional performance counters as warnings, not fatal errors.
- Never fabricate unavailable measurements.
- Record collection errors in machine-readable output.
- Produce `configuration-baseline.json` as defined in `FLEXERA-IIS-BASELINE.md`.
- Produce `security-audit.json` and `security-audit.csv` as defined in `SECURITY-AUDIT.md`.
- Resolve inherited IIS security configuration to the effective value for each selected Flexera endpoint.
- Preserve configuration provenance (server/site/application/path scope) where relevant.
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
- IIS configuration inheritance/effective-value resolution,
- WebDAV detection,
- Request Filtering detection for known Flexera extensions,
- Basic Authentication + HTTP/HTTPS decision logic,
- Flexera compatibility-exception handling,
- role-service-installed versus site-feature-enabled distinction,
- certificate metadata collection without private-key export,
- secret redaction,
- missing IIS prerequisite handling.

Sanitize all committed IIS log/config fixtures.

## Before declaring a task complete

Confirm that the change:

- remains inside the defined IIS-only scope,
- follows `FLEXERA-IIS-BASELINE.md` and `SECURITY-AUDIT.md`,
- does not modify production IIS/Flexera configuration by default,
- works without a fixed worker PID,
- handles missing data explicitly,
- does not mislabel project heuristics as Flexera or Microsoft recommendations,
- represents product-specific exceptions explicitly rather than silently overriding a benchmark,
- does not expose credentials or secret material,
- updates documentation when behavior, controls or output schemas change,
- includes or updates tests for parsing/statistical/security logic.
