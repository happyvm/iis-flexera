# CLAUDE.md

This repository defines a PowerShell monitoring tool for the **IIS workload of a Flexera Inventory Beacon**.

Before implementing or reviewing code, read:

1. [`SPECIFICATION.md`](SPECIFICATION.md) — functional and technical source of truth.
2. [`FLEXERA-IIS-BASELINE.md`](FLEXERA-IIS-BASELINE.md) — normative Flexera-specific IIS requirements, recommendations and topology rules.
3. [`AGENTS.md`](AGENTS.md) — implementation constraints and safety rules.
4. [`README.md`](README.md) — project overview and intended workflow.

## Core rule

Keep the first version strictly focused on IIS:

- IIS topology discovery,
- Flexera-related sites/applications,
- `ManageSoftRL` / `ManageSoftDL` discovery and attribution,
- Application Pools,
- `w3wp.exe` worker processes,
- HTTP.sys queues,
- IIS performance counters,
- IIS W3C logs,
- Flexera IIS configuration-baseline checks,
- statistical analysis and Markdown reporting.

Do not turn the project into a generic Flexera Beacon monitor unless explicitly asked.

## Flexera-specific review requirements

Do not assume that an AppPool named `Flexera Beacon` is necessarily the pool serving downstream agent traffic. Resolve the real IIS topology from the Flexera endpoints.

Account for Flexera's documented differences between standalone and co-installed Beacon authentication layouts. Do not mark a configuration non-compliant unless the topology is known well enough to apply the relevant rule.

Treat Flexera's IIS prerequisites and recommendations as observable configuration evidence:

- HTTP Logging,
- ASP.NET/.NET IIS prerequisites,
- static/dynamic compression,
- authentication features,
- WebDAV state,
- Request Filtering and known Flexera package extensions,
- HTTP/HTTPS bindings and custom ports.

Never remediate these settings automatically.

Flexera does not provide universal IIS CPU, memory, request-rate, P95/P99 latency or HTTP.sys queue thresholds in the reviewed documentation. Do not present invented thresholds as Flexera recommendations. Any future heuristic must be explicitly labeled as an `iis-flexera` heuristic.

## Preferred development approach

Implement in small, testable increments. Preserve raw data before adding higher-level analysis. Avoid UI/dashboard work until the collector, baseline checks, log parser and statistics are correct.

Target Windows PowerShell 5.1 and native Windows/IIS interfaces for v0.1. Treat production safety and low overhead as hard requirements.

A read-only inspection of narrowly scoped Flexera web-server configuration metadata is permitted when needed to discover or explain IIS behavior; unrelated BeaconEngine monitoring remains out of scope.

When changing behavior, schemas, Flexera assumptions or baseline rules, update the relevant normative documentation in the same change.
