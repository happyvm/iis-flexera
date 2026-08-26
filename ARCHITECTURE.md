# Architecture and diagnostic boundaries

## Bugs identified in the previous implementation

1. `Select-ByDate` parsed offset-bearing CSV timestamps into `DateTime` values
   and compared them with naive local-midnight values. W3C UTC dates and local
   collector dates could consequently be assigned to different days.
2. Numeric extraction used PowerShell truthiness, which discarded valid zero
   queue, connection and rejected-request values.
3. Optional collector files were loaded directly. Invalid JSON/CSV aborted the
   analysis, while absent, empty and out-of-window inputs were indistinguishable.
4. W3C normalization omitted client/server address, User-Agent, username, Host
   and protocol fields needed to investigate HTTP 405 responses.
5. Worker rows lacked cumulative CPU evidence, virtual bytes, process start,
   uptime and the number of simultaneous workers in a Web Garden.
6. The baseline exposed only a small flattened AppPool subset and no effective
   handler/module or detailed Request Filtering evidence.

## Component model

- **Collectors** (`Monitor-FlexeraBeaconIIS.ps1`, `src/WorkerProcess.ps1`,
  `src/PerformanceCounters.ps1`) refresh live topology, batch native reads and
  write UTC observations. They never modify IIS or Flexera.
- **Input and normalization** (`src/InputData.ps1`, `src/Time.ps1`,
  `src/IisLogs.ps1`) classify optional files, normalize timestamps to UTC and
  map configurable W3C fields into a stable record shape.
- **Analysis** (`src/Statistics.ps1`) performs percentiles, status/405,
  endpoint and transfer calculations without vendor thresholds.
- **Configuration/security evidence** (`src/ConfigurationBaseline.ps1`,
  `src/SecurityAudit.ps1`) reads effective IIS settings and keeps Microsoft,
  Flexera and project interpretation separate.
- **Presentation** (`src/Reporting.ps1`) renders evidence, limitations and
  cautious next investigations. Display timezone conversion happens only here;
  calculations remain UTC.

## Interpretation limits

W3C `time-taken` is not pure application execution time. Response transfer,
client bandwidth and network behavior may contribute. A request cannot be
attributed to one worker PID from standard W3C fields alone; the report can only
correlate it with workers active in the same time window unless additional
explicit tracing is enabled outside the default read-only workflow.

No custom AppPool value is treated as defective merely because it differs from
an IIS default. No setting is labeled a Flexera recommendation without explicit
vendor evidence in the normative baseline/security documents.
