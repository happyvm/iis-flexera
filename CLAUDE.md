# CLAUDE.md

This repository defines a PowerShell monitoring and read-only security assessment tool for the **IIS workload of a Flexera Inventory Beacon**.

Before implementing or reviewing code, read:

1. [`SPECIFICATION.md`](SPECIFICATION.md) — functional and technical source of truth.
2. [`FLEXERA-IIS-BASELINE.md`](FLEXERA-IIS-BASELINE.md) — normative Flexera-specific IIS requirements, recommendations and topology rules.
3. [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) — normative security comparison between observed configuration, Microsoft IIS guidance and Flexera guidance.
4. [`AGENTS.md`](AGENTS.md) — implementation constraints and safety rules.
5. [`README.md`](README.md) — project overview and intended workflow.

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
- read-only IIS security posture assessment,
- statistical analysis and Markdown reporting.

Do not turn the project into a generic Flexera Beacon monitor unless explicitly asked.

## Security review model

Security findings must be evaluated as:

```text
Observed configuration
vs Microsoft IIS guidance
vs Flexera guidance
=> Effective Flexera-compatible recommendation
```

Do not blindly apply a generic IIS benchmark if it breaks a documented Flexera requirement.

Use the status model in `SECURITY-AUDIT.md`, including `FLEXERA_EXCEPTION` and `CONFLICT` when appropriate. Do not collapse results into a single percentage security score for v0.1.

Distinguish:

- Flexera mandatory requirements,
- Flexera recommendations,
- optional Flexera security enhancements,
- Flexera compatibility constraints,
- generic Microsoft IIS hardening observations.

Examples requiring special attention:

- HTTPS is Flexera's preferred first security step for Inventory Beacons.
- Current Flexera documentation for IIS-based agent communication uses standard ports 80/443; do not treat arbitrary custom IIS ports as automatically equivalent.
- Basic Authentication must not be accepted as secure over HTTP.
- Anonymous authentication is explicitly preferred by Flexera where possible because of Inventory Agent/failover behavior; this can be a product-specific exception to generic upload-authentication guidance.
- Mutual TLS is supported as an optional enhanced-security model.
- WebDAV must be disabled for the relevant Flexera IIS paths.
- Request Filtering should remain enabled/hardened where appropriate but must not block Flexera payload extensions such as `.osd`, `.npl`, `.nds` and `.ini`.
- Distinguish an installed IIS role service from the effective site/path feature state. For example, the Directory Browsing role/module may be present while directory browsing remains disabled at the Flexera endpoint.
- AppPool identities should be low privilege and isolated unless a documented Flexera design requires otherwise.
- Certificate/private-key/credential material must never be exported.

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
- HTTP/HTTPS bindings,
- certificate metadata,
- relevant certificate-validation/revocation preferences when safely readable.

Never remediate these settings automatically.

Flexera does not provide universal IIS CPU, memory, request-rate, P95/P99 latency or HTTP.sys queue thresholds in the reviewed documentation. Do not present invented thresholds as Flexera recommendations. Any future heuristic must be explicitly labeled as an `iis-flexera` heuristic.

## Preferred development approach

Implement in small, testable increments. Preserve raw data before adding higher-level analysis. Avoid UI/dashboard work until the collector, baseline checks, log parser, statistics and audit logic are correct.

Target Windows PowerShell 5.1 and native Windows/IIS interfaces for v0.1. Treat production safety and low overhead as hard requirements.

A read-only inspection of narrowly scoped Flexera web/security configuration metadata is permitted when needed to discover or explain IIS behavior; unrelated BeaconEngine monitoring remains out of scope.

When changing behavior, schemas, Flexera assumptions, security controls or baseline rules, update the relevant normative documentation in the same change.
