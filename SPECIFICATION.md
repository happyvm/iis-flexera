# IIS Flexera Monitor — Functional and Technical Specification

## 1. Purpose

This document defines the first implementation target for `iis-flexera`.

The tool is intended to observe **only the IIS-facing workload of a Flexera Inventory Beacon** for a representative period (seven days by default) and generate enough evidence to characterize workload, saturation, errors and sizing.

The implementation should be usable by Codex, Claude or a human developer without requiring additional interpretation of the project goal.

---

## 2. Primary use case

An administrator wants to understand the real IIS behavior of a Flexera Inventory Beacon before making a capacity or architecture decision.

Typical questions:

- What is the normal and peak HTTP request rate?
- Are requests bursty or evenly distributed?
- What are the P50/P95/P99 response times?
- Does HTTP.sys ever queue requests?
- Does IIS ever reject requests?
- Which Flexera endpoints account for most traffic?
- What CPU and memory are consumed by the relevant IIS worker process(es)?
- Does the Application Pool recycle during the measurement period?
- Is an observed CPU/memory peak correlated with increased request volume or latency?

The collector must produce data that can answer these questions after the run has completed.

---

## 3. Non-goals

The first implementation is not a complete Flexera Beacon health-monitoring solution.

Do not add collection for:

- BeaconEngine.
- Inventory import jobs.
- Oracle discovery/inventory.
- Database connectors.
- Scheduled Flexera tasks.
- SQL Server performance.
- Generic server monitoring beyond values directly required to understand IIS.
- External monitoring platforms.

Do not modify IIS settings in order to improve performance. The tool is an observer.

---

## 4. Supported platform

Initial target:

- Windows Server hosting a Flexera Inventory Beacon.
- IIS installed and used for Beacon HTTP communications.
- Windows PowerShell 5.1 as the minimum PowerShell target unless a technical blocker is identified.

PowerShell 7 compatibility is desirable but must not require PowerShell 7.

The implementation should avoid third-party PowerShell modules for the first version.

---

## 5. Flexera/IIS discovery

### 5.1 Requirement

The tool must not assume that all installations expose the same site, application, virtual-directory or Application Pool names.

Known Flexera endpoints include:

- `ManageSoftRL` — reporting/upload location.
- `ManageSoftDL` — download location.

The implementation should use these names as **discovery hints**, not as the only accepted configuration.

### 5.2 Discovery sources

Use native IIS interfaces such as:

- `Microsoft.Web.Administration` when available.
- `appcmd.exe`.
- IIS configuration files/APIs where appropriate.

The collector should discover and persist:

- IIS version.
- Site name and site ID.
- Site bindings.
- Applications.
- Virtual directories.
- Physical paths where useful.
- Application Pool names.
- Application Pool runtime state.
- Application Pool queue length configuration.
- Maximum worker process count (web garden configuration).
- Current worker-process PID(s).

### 5.3 Selection logic

The first version should:

1. Enumerate IIS applications and virtual directories.
2. Find entries matching known Flexera locations (`ManageSoftRL`, `ManageSoftDL`) where present.
3. Resolve their parent site(s) and Application Pool(s).
4. If multiple candidate Flexera pools/sites exist, monitor all candidates and record the selection decision.
5. If no known Flexera endpoint is found, allow explicit parameters such as `-SiteName` and/or `-AppPoolName`.
6. If discovery remains ambiguous, terminate before starting the seven-day run with a clear diagnostic message rather than silently monitoring the wrong pool.

---

## 6. Worker-process tracking

### 6.1 Requirement

The monitor must track the `w3wp.exe` process(es) belonging to the selected Application Pool(s).

A PID is not stable for the duration of a seven-day run. IIS can recycle a pool and replace the process.

### 6.2 PID mapping

A supported mapping method is:

```text
%windir%\System32\inetsrv\appcmd.exe list wps
```

Example output:

```text
WP "3577" (apppool:Flexera Beacon)
```

The implementation may use a more structured API where practical, but it must refresh the mapping periodically and after observed process termination.

### 6.3 Overlapped recycle

During an overlapped recycle, two worker processes may temporarily exist for the same pool.

The collector must therefore support **zero, one or multiple PIDs per AppPool** at a given sample.

It must not treat the presence of two worker processes as an error.

---

## 7. Sampling model

### 7.1 Defaults

Default values:

```text
Duration        = 7 days
SampleInterval  = 15 seconds
```

Both must be configurable.

Suggested parameters:

```powershell
-Duration
-SampleIntervalSeconds
-OutputPath
-SiteName
-AppPoolName
```

### 7.2 Timing

Each sample must carry a high-resolution timestamp.

Use a consistent timestamp format, preferably ISO 8601 with timezone information, for example:

```text
2026-08-26T08:15:30.123+02:00
```

For request logs, preserve the IIS log time semantics and normalize to a documented time basis during analysis.

### 7.3 Missed samples

A collection error must not terminate the run unless continuing would produce misleading data.

For recoverable errors:

- write an error/warning record,
- continue collection,
- leave the affected values empty/null,
- increment a collector-error count.

---

## 8. IIS performance data

The collector should use Windows performance counters where available.

### 8.1 Web Service counters

For each selected IIS site, collect where supported:

```text
\Web Service(<site>)\Current Connections
\Web Service(<site>)\Connection Attempts/sec
\Web Service(<site>)\Bytes Received/sec
\Web Service(<site>)\Bytes Sent/sec
\Web Service(<site>)\Bytes Total/sec
\Web Service(<site>)\Get Requests/sec
\Web Service(<site>)\Post Requests/sec
\Web Service(<site>)\Total Method Requests/sec
```

Counter names can vary slightly with Windows/IIS versions. The implementation should probe availability rather than fail because one optional counter is missing.

### 8.2 HTTP.sys request queue counters

Collect for the queue(s) associated with the monitored Application Pool(s), where available:

```text
\HTTP Service Request Queues(<queue>)\CurrentQueueSize
\HTTP Service Request Queues(<queue>)\RejectedRequests
\HTTP Service Request Queues(<queue>)\ArrivalRate
```

`CurrentQueueSize = 0` is valid and usually means requests are being handled without waiting in the kernel request queue.

The implementation must record the performance-counter instance name used for each Application Pool.

### 8.3 Process counters

For each selected `w3wp.exe` PID collect:

- CPU usage.
- Working Set.
- Private Bytes.
- Thread Count.
- Handle Count.

Prefer PID-safe collection rather than relying only on the process-instance string `w3wp`, `w3wp#1`, etc., because those instance names can be reassigned after process churn.

Possible implementation approaches include:

- WMI/CIM formatted performance classes keyed by `IDProcess`.
- process CPU deltas calculated from process CPU time and elapsed wall time.
- mapping `Process(w3wp*)\ID Process` to the correct performance-counter instance.

The chosen method must be documented in code comments and tested across a worker-process recycle.

### 8.4 CPU normalization

The report must clearly define whether CPU percentage is:

- percentage of one logical processor, or
- normalized percentage of total machine CPU capacity.

Prefer a normalized 0–100% value for human-readable reporting while retaining enough raw information to reproduce calculations.

---

## 9. IIS W3C log analysis

### 9.1 Principle

Performance counters characterize load and resource use. IIS request logs explain **what traffic produced that load**.

The analyzer must therefore parse IIS W3C logs for the selected site(s).

### 9.2 Required fields

Use the following fields when present:

```text
date
time
s-sitename
cs-method
cs-uri-stem
cs-uri-query
sc-status
sc-substatus
sc-win32-status
cs-bytes
sc-bytes
time-taken
```

Additional fields may be retained, but the project must not require personally identifying client data for its primary report.

### 9.3 Header-driven parsing

W3C log field order is configurable.

The parser must read lines such as:

```text
#Fields: date time s-ip cs-method cs-uri-stem ...
```

and build the parser from that field definition.

Never use a fixed positional schema without reading `#Fields:`.

### 9.4 Log rotation

The analyzer must support multiple IIS log files covering the observation period.

It must not assume the run fits into one file.

### 9.5 `time-taken`

IIS records `time-taken` in milliseconds.

The report should calculate:

- mean,
- P50,
- P90 (optional),
- P95,
- P99,
- max.

Percentiles should be reported globally and, where sample size is sufficient, per endpoint.

### 9.6 URI normalization

By default, aggregate using `cs-uri-stem` without query parameters.

`cs-uri-query` should not be used as part of the endpoint grouping key unless explicitly requested, because highly variable query parameters can fragment statistics and may contain sensitive values.

---

## 10. HTTP analysis

The final analysis must provide at least:

### 10.1 Volume

- Total request count.
- Requests by method.
- Requests by endpoint.
- Requests by hour/day.
- Average requests per second over the complete observation period.
- Active-period request rate where useful.

### 10.2 Response codes

Counts and percentages for:

- 2xx.
- 3xx.
- 4xx.
- 5xx.

Also include the most frequent exact status/substatus combinations.

Examples:

```text
200
401.2
404.0
500.0
503.0
```

`sc-win32-status` should be included when diagnosing failures.

### 10.3 Bandwidth

Calculate from IIS logs and/or counters:

- bytes received,
- bytes sent,
- total bytes,
- top endpoints by received bytes,
- top endpoints by sent bytes.

### 10.4 Latency

Calculate P50/P95/P99/max:

- globally,
- per important endpoint,
- by hour when useful for correlation.

Avoid declaring an endpoint "slow" solely from a very small number of requests. Include request counts with percentile tables.

---

## 11. Application Pool events

The collector should detect and record:

- pool started,
- pool stopped,
- worker process started,
- worker process stopped,
- PID changed,
- overlapped recycle inferred from concurrent old/new PIDs.

If useful and reliable, Windows Event Log entries from IIS/WAS may supplement this data.

The first version should avoid enabling additional verbose tracing on production systems automatically.

---

## 12. Output model

A collection run should create a unique directory.

Example:

```text
output/
└── 2026-08-26_081500/
    ├── metadata.json
    ├── iis-counters.csv
    ├── worker-processes.csv
    ├── apppool-events.csv
    ├── collector-events.csv
    ├── summary.json
    └── report.md
```

Raw IIS logs do not need to be copied by default if their original paths, file names and time ranges are recorded in metadata and they remain available for analysis.

A future option may support copying only the relevant log files into the run directory for offline analysis.

---

## 13. Suggested data schemas

### 13.1 `metadata.json`

Suggested structure:

```json
{
  "schemaVersion": 1,
  "toolVersion": "0.1.0",
  "computerName": "BEACON01",
  "collectionStart": "2026-08-26T08:15:00+02:00",
  "collectionEnd": null,
  "sampleIntervalSeconds": 15,
  "iis": {
    "version": "10.0",
    "sites": [],
    "applications": [],
    "applicationPools": []
  },
  "logSources": [],
  "warnings": []
}
```

### 13.2 `iis-counters.csv`

Minimum conceptual columns:

```text
Timestamp
SiteName
AppPoolName
CurrentConnections
ConnectionAttemptsPerSec
RequestsPerSec
BytesReceivedPerSec
BytesSentPerSec
QueueSize
RejectedRequests
ArrivalRate
```

Actual CSV headers should remain stable once version 1 is released.

### 13.3 `worker-processes.csv`

```text
Timestamp
AppPoolName
PID
CPUPercent
WorkingSetBytes
PrivateBytes
ThreadCount
HandleCount
```

### 13.4 `apppool-events.csv`

```text
Timestamp
AppPoolName
EventType
PID
PreviousPID
Details
```

Possible `EventType` values:

```text
PoolStarted
PoolStopped
WorkerStarted
WorkerStopped
WorkerChanged
OverlappedRecycle
```

---

## 14. Report requirements

The report should be useful to an infrastructure architect without requiring manual CSV analysis.

Minimum sections:

1. Executive summary.
2. Observation period and collection quality.
3. Discovered IIS/Flexera topology.
4. HTTP traffic profile.
5. Response-time profile.
6. HTTP error profile.
7. IIS worker-process CPU and memory profile.
8. HTTP.sys queue behavior.
9. Application-pool lifecycle events.
10. Top endpoints.
11. Capacity observations.
12. Collection limitations/warnings.

### 14.1 Required summary statistics

At minimum:

```text
Requests total
Requests/sec average
Requests/sec P50/P95/P99/max
Current connections P50/P95/P99/max
Latency P50/P95/P99/max
CPU P50/P95/P99/max
Private Bytes P50/P95/P99/max
Queue size P50/P95/P99/max
Rejected requests total
HTTP 4xx total and percentage
HTTP 5xx total and percentage
Worker process recycle count
```

### 14.2 Capacity wording

The report should not invent arbitrary universal thresholds for sizing.

Prefer observations such as:

```text
Observed P95 CPU was 18% and maximum CPU was 41% during the seven-day window.
No HTTP.sys queueing or rejected requests were observed.
```

rather than unsupported claims such as:

```text
CPU below 70% means the server is correctly sized.
```

Threshold-based recommendations may be added later if they are explicitly documented as project policy rather than Microsoft/Flexera limits.

---

## 15. Runtime safety

The collector is intended to run on production Beacons, so it must follow these rules:

- Do not restart IIS.
- Do not recycle Application Pools.
- Do not alter Application Pool settings.
- Do not change Flexera configuration.
- Do not enable Failed Request Tracing automatically.
- Do not enable ETW tracing automatically.
- Do not change IIS logging fields automatically without an explicit future opt-in feature.
- Do not collect memory dumps.
- Avoid high-frequency WMI queries that create measurable overhead.
- Keep files append-only during collection where practical.

The implementation should measure its own collection errors and, if feasible, record approximate output volume.

---

## 16. Log-field validation

At startup, inspect the selected site's logging configuration and/or first available W3C `#Fields:` declaration.

If important fields are missing:

- continue collecting performance counters,
- explicitly list missing fields,
- explain which analyses will not be available.

Examples:

- no `time-taken` -> latency percentiles unavailable,
- no `sc-substatus` -> detailed IIS status breakdown unavailable,
- no `cs-bytes` -> inbound request-byte analysis unavailable.

The tool must not silently fabricate unavailable metrics.

---

## 17. CLI proposal

Initial command shape:

```powershell
.\Monitor-FlexeraBeaconIIS.ps1 \
    -Duration 7.00:00:00 \
    -SampleIntervalSeconds 15 \
    -OutputPath C:\FlexeraIISMonitor\output
```

Optional overrides:

```powershell
-SiteName "Default Web Site"
-AppPoolName "Flexera Beacon"
```

A short validation run must be possible, for example:

```powershell
.\Monitor-FlexeraBeaconIIS.ps1 \
    -Duration 00:10:00 \
    -SampleIntervalSeconds 5
```

This is essential for development and acceptance testing.

---

## 18. Proposed implementation structure

The exact file layout may evolve, but a clean separation between collection and analysis is required.

Suggested structure:

```text
Monitor-FlexeraBeaconIIS.ps1
Analyze-FlexeraBeaconIIS.ps1
src/
  Discovery.ps1
  PerformanceCounters.ps1
  WorkerProcess.ps1
  IisLogs.ps1
  Statistics.ps1
  Reporting.ps1
tests/
  Discovery.Tests.ps1
  IisLogs.Tests.ps1
  Statistics.Tests.ps1
fixtures/
  iis-logs/
```

If the project stays sufficiently small, modules can be consolidated. Do not create unnecessary abstractions merely to match this example.

---

## 19. Testing requirements

### 19.1 Unit tests

Tests should cover at least:

- parsing W3C headers,
- parsing multiple W3C field orders,
- skipped/comment log lines,
- malformed log rows,
- status-code classification,
- percentile calculations,
- URI aggregation,
- PID/AppPool mapping parsing if `appcmd` output is parsed as text.

Pester is acceptable for PowerShell tests.

### 19.2 Integration tests

Where IIS is available, verify:

- site discovery,
- AppPool discovery,
- worker-process PID mapping,
- process tracking across a manual recycle,
- collection while an AppPool is temporarily stopped,
- HTTP.sys queue instance discovery.

### 19.3 Test fixtures

Commit sanitized IIS W3C sample logs with different `#Fields:` orders.

Do not commit production Flexera logs or sensitive URLs/query strings.

---

## 20. Acceptance criteria for version 0.1

Version 0.1 is acceptable when all of the following are true:

1. A short test run can start and stop unattended.
2. Flexera-related IIS topology is auto-discovered or can be explicitly selected.
3. The selected AppPool is mapped to the correct `w3wp.exe` PID.
4. A PID change caused by an AppPool recycle does not break collection.
5. CPU, memory, connection and HTTP.sys queue samples are written with timestamps.
6. Missing optional counters do not abort the collection.
7. IIS W3C logs are parsed using their `#Fields:` definitions.
8. Request counts, status classes and latency percentiles are calculated correctly.
9. A Markdown report and machine-readable summary are generated.
10. Collector errors and missing data are visible in the report.
11. The tool does not modify IIS/Flexera configuration during normal operation.
12. A seven-day run can be performed without requiring an interactive PowerShell session to remain open.

---

## 21. Open design decisions

These items should be resolved during implementation rather than guessed silently:

- Best unattended execution model: scheduled task, detached PowerShell process, or both.
- Whether raw request rows should be normalized into `requests.csv` or analyzed directly from W3C files.
- Whether to collect only aggregate site counters or also per-application information when exposed.
- Best PID-safe mechanism for process performance counters on the oldest supported Windows Server version.
- Whether the report should include SVG/PNG charts in v0.1 or remain Markdown/tabular.
- Whether a future mode should temporarily add missing IIS W3C log fields with explicit administrator approval.

Document the chosen answers in the repository when implementation begins.

---

## 22. Implementation priority

Recommended order:

1. IIS/Flexera discovery.
2. Worker-process/AppPool mapping.
3. Reliable timed collection loop.
4. CSV/JSON output schemas.
5. IIS W3C parser.
6. Statistical analysis.
7. Markdown report.
8. Tests.
9. Seven-day production validation.
10. Optimization and optional visualization.

Do not begin with dashboards or UI. Reliable raw collection and correct attribution to the Flexera IIS workload are the priority.

---

## 23. References

Flexera:

- Inventory Beacon overview: https://docs.flexera.com/fnms/inventory-beacon
- Configuring Inventory Collection: https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection
- IIS Application Pools: https://docs.flexera.com/fnms/inventory-beacon-overview/fib-ref-introduction/iis-application-pools

Microsoft:

- AppCmd: https://learn.microsoft.com/en-us/iis/get-started/getting-started-with-iis/getting-started-with-appcmdexe
- Troubleshoot high CPU in an IIS Application Pool: https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/site-behavior-performance/troubleshoot-high-cpu-in-iis-app-pool
- IIS `time-taken`: https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/time-taken-field-http-log
- IIS W3C log settings: https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/
