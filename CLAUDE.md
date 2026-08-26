# CLAUDE.md

This repository defines a PowerShell monitoring tool for the **IIS workload of a Flexera Inventory Beacon**.

Before implementing or reviewing code, read:

1. [`SPECIFICATION.md`](SPECIFICATION.md) — functional and technical source of truth.
2. [`AGENTS.md`](AGENTS.md) — implementation constraints and safety rules.
3. [`README.md`](README.md) — project overview and intended workflow.

## Core rule

Keep the first version strictly focused on IIS:

- IIS topology discovery,
- Flexera-related sites/applications,
- Application Pools,
- `w3wp.exe` worker processes,
- HTTP.sys queues,
- IIS performance counters,
- IIS W3C logs,
- statistical analysis and Markdown reporting.

Do not turn the project into a generic Flexera Beacon monitor unless explicitly asked.

## Preferred development approach

Implement in small, testable increments. Preserve raw data before adding higher-level analysis. Avoid UI/dashboard work until the collector, log parser and statistics are correct.

Target Windows PowerShell 5.1 and native Windows/IIS interfaces for v0.1. Treat production safety and low overhead as hard requirements.

When changing behavior, schemas or assumptions, update `SPECIFICATION.md` in the same change.
