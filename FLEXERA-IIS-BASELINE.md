# Flexera IIS Baseline for Inventory Beacons

## Purpose

This document records the **Flexera-specific IIS requirements, recommendations and topology rules** that must be taken into account by `iis-flexera`.

It is normative for the project together with [`SPECIFICATION.md`](SPECIFICATION.md).

The monitor remains read-only: these checks are used to discover, validate and explain the monitored configuration. The tool must **not** automatically remediate IIS or Flexera settings.

The recommendations below are derived from current Flexera One / FlexNet Manager Suite documentation. Where Flexera does not publish a performance threshold, this project must not invent one and label it as a Flexera recommendation.

---

## 1. Supported IIS prerequisites

Flexera documents IIS 7.0 or later for an Inventory Beacon using IIS. Current Flexera One prerequisites also require ASP.NET support and list the following IIS role services/features for an IIS-based beacon:

- `.NET Extensibility 4.5` or the corresponding supported later .NET 4.x feature.
- `ASP.NET 4.5+` or corresponding supported later .NET 4.x feature.
- ISAPI Extensions.
- HTTP Errors.
- Static Content.
- HTTP Logging.
- Dynamic Content Compression.
- Static Content Compression.
- Basic Authentication.
- Windows Authentication.

### Monitoring implication

At startup the collector should perform a **read-only prerequisite inventory** and record whether these relevant IIS capabilities are present.

The report should distinguish:

- `Present`
- `Missing`
- `Not detectable`
- `Not applicable`

A missing prerequisite is configuration evidence, not a reason to silently change the server.

HTTP Logging is particularly important to this project because request-level latency, status and endpoint analysis depends on W3C logs.

Reference:

- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon/prerequisites-for-inventory-beacons

---

## 2. Flexera HTTP endpoints

Flexera uses well-known locations on Inventory Beacons, including:

- `ManageSoftRL` — reporting location used for uploads from inventory clients.
- `ManageSoftDL` — download location used by inventory clients for policy/packages and related content.

These names are strong discovery hints but must not be treated as proof that every deployment uses an identical IIS site or Application Pool layout.

### Monitoring implication

Discovery should first locate `ManageSoftRL` and `ManageSoftDL`, then resolve:

1. IIS site.
2. IIS application or virtual directory.
3. physical path.
4. Application Pool.
5. current worker-process PID(s).
6. site bindings/protocol/port.
7. authentication settings at the relevant IIS scope.

The report should keep upload and download traffic separate where the IIS log data allows this.

References:

- https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection
- https://docs.flexera.com/flexera/EN/ITAssets/ConfiguringDirectInvGathering.htm

---

## 3. Authentication topology matters

Flexera's documented authentication behavior depends on the Beacon topology.

### 3.1 Standalone Inventory Beacon

For a standalone Inventory Beacon, Flexera documents that `ManageSoftRL` and `ManageSoftDL` share the same directory and `web.config`. Consequently, both locations must use the same authentication method.

If Basic Authentication is selected in the Beacon configuration, IIS must be configured consistently for both locations. Flexera documents HTTP 409 upload failures when the Basic Authentication configuration does not match.

### 3.2 Beacon co-installed with central server roles

When the Inventory Beacon is co-installed on the batch/application server, Flexera documents a topology in which authentication may differ between the two locations, for example:

- `ManageSoftRL`: Basic Authentication.
- `ManageSoftDL`: Anonymous Authentication.

Therefore the monitor must **not** apply a universal rule stating that both endpoints always require the same authentication.

### 3.3 Anonymous authentication recommendation

Flexera states that, wherever possible, IIS on Inventory Beacons should be configured for anonymous authentication so installed FlexNet Inventory Agents can freely access the Beacon web service.

This must be interpreted in the context of the deployment topology and any explicitly configured Basic Authentication requirements.

### Monitoring implication

The collector should record, without changing:

- Anonymous Authentication enabled/disabled.
- Basic Authentication enabled/disabled.
- Windows Authentication enabled/disabled.
- the IIS configuration scope at which the setting was resolved.

The report may flag an **authentication consistency warning** when it can confidently identify a standalone Beacon whose `ManageSoftRL` and `ManageSoftDL` settings conflict.

If topology cannot be determined reliably, report the observed values without declaring the configuration non-compliant.

Never collect or persist passwords.

#### Implementation status (iis-flexera v0.1)

This rule is implemented as control `FB-IIS-BASE-001` in `configuration-baseline.json`'s `AuthenticationConsistency` array (`src/ConfigurationBaseline.ps1`). Topology is inferred by comparing the `ManageSoftRL`/`ManageSoftDL` physical paths: an identical path is reported as `Standalone` and mismatched authentication then produces a `FAIL` (citing the documented HTTP 409 upload failure); a differing path is reported as `Distinct` and the finding is `NOT_APPLICABLE` rather than a failure, per the rule above. `Distinct` is a neutral label, not an assertion that the topology is co-installed.

References:

- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon/prerequisites-for-inventory-beacons
- https://docs.flexera.com/flexera/EN/ITAssets/ConfiguringDirectInvGathering.htm
- https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection

---

## 4. HTTP vs HTTPS and certificates

Flexera supports IIS for HTTPS-based communications and documents IIS as the web server used for mutual TLS configurations.

For Flexera One upstream communication, current system requirements specify HTTPS/TLS requirements separately from the downstream Inventory Agent-to-Beacon web service.

The monitor must therefore avoid assuming that every observed Beacon IIS binding is HTTP/80 or HTTPS/443.

### Monitoring implication

Record:

- binding protocol (`http` / `https`).
- IP binding.
- configured port.
- host name where present.
- certificate thumbprint for HTTPS only if available through safe metadata APIs.
- certificate subject/issuer/expiry where available and useful.

Do **not** export certificate private keys or secrets.

The monitor should treat custom ports as valid.

References:

- https://docs.flexera.com/FlexNetManagerSuite2022R1/EN/WebHelp/tasks/ConfigureMutualTLS.html
- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/adjusting-the-web-server-on-the-inventory-beacon
- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon/prerequisites-for-inventory-beacons

---

## 5. WebDAV must not interfere with Flexera inventory traffic

Flexera's installation guidance requires WebDAV to be disabled for an Inventory Beacon using IIS because WebDAV can intercept HTTP processing and block FlexNet inventory functionality.

### Monitoring implication

Add a read-only preflight check for WebDAV configuration relevant to the monitored site/server.

The result should appear in the configuration baseline as one of:

- `Disabled`
- `Enabled`
- `Not installed`
- `Unknown`

If WebDAV is enabled for the effective Flexera path, report a warning and cite the Flexera baseline. Do not disable it automatically.

Reference:

- https://docs.flexera.com/fnms-install/upgrade-guide/prerequisites-and-preparations/configure-net-and-iis

---

## 6. Request Filtering must not block Flexera package extensions

Flexera notes that IIS Request Filtering may be enabled, but administrators must ensure that extensions expected by the FlexNet Inventory Agent are not filtered. Flexera explicitly gives examples including:

- `.osd`
- `.npl`
- `.nds`
- `.ini`

### Monitoring implication

If Request Filtering is installed/enabled, inspect its effective deny/allow rules for the Flexera endpoint(s).

The project should report potential blocking rules as configuration warnings.

Do not change Request Filtering automatically.

Reference:

- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon/prerequisites-for-inventory-beacons

---

## 7. IIS logging is part of the Flexera prerequisite baseline

Flexera explicitly lists **HTTP Logging** among the required IIS role services for a Beacon using IIS.

This aligns with the project requirement to analyze W3C logs.

### Monitoring implication

Preflight must record:

- whether HTTP Logging is installed.
- whether logging is enabled for the selected site.
- log format.
- log directory.
- rollover configuration when discoverable.
- effective W3C `#Fields:` encountered in the selected logs.

For project analytics, the following fields remain strongly preferred:

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

If one or more fields are absent, the monitor must explain the unavailable analyses rather than modify IIS logging.

#### Implementation status (iis-flexera v0.1)

`New-FlexeraConfigurationBaseline` (`src/ConfigurationBaseline.ps1`) captures a `Logging` entry per selected site: whether a `logFile` section could be read, its `LogFormat`/`Directory`, and the effective W3C fields (mapped from IIS's `logExtFileFlags` names). `Test-RequiredW3CFieldsPresent` compares that against the required-field list above and records, per missing field, exactly which analysis becomes unavailable - this preflight check runs before the sampling loop starts (`Monitor-FlexeraBeaconIIS.ps1`) and the missing-field/impact pairs are written to `collector-events.csv` as `WARNING` entries. IIS does not expose one universal "logging enabled" boolean once the HTTP Logging role service is present, so `Enabled` reflects the `logFile` section's presence as the closest available signal; this must be validated against a real IIS host. Field mapping only applies when `LogFormat` is `W3C`.

---

## 8. Compression is part of the Flexera IIS prerequisite set

Flexera lists both Static Content Compression and Dynamic Content Compression in its IIS prerequisites.

### Monitoring implication

Record whether these role services are present.

The first version does not need to calculate compression ratios. Their presence belongs in the baseline because it can materially affect network volume and CPU interpretation.

Reference:

- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon/prerequisites-for-inventory-beacons

---

## 9. Relevant Flexera web-server configuration may be read as metadata

Flexera documents additional local web-server settings in `BeaconEngine.config`, normally located at:

```text
C:\Program Files\Flexera Software\Inventory Beacon\DotNet\conf\BeaconEngine.config
```

Relevant settings can include, depending on version/configuration:

- web-server selection.
- `protocol`.
- `networkname`.
- `authenticationType`.
- `allowedExtensions`.
- `maxDownloadMessageSizekB` (documented default: 30720 kB).

### Monitoring implication

Although the project does not monitor BeaconEngine performance, it may **read only the web-server-related configuration metadata** required to explain IIS behavior or validate discovery.

Rules:

- never modify the file.
- never persist passwords or encrypted password values.
- ignore unrelated BeaconEngine configuration.
- treat file absence/version differences as non-fatal.
- IIS remains the authoritative source for the effective IIS configuration.

Reference:

- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/adjusting-the-web-server-on-the-inventory-beacon

---

## 10. Application Pool names depend on server role

Flexera documents Application Pools named `Flexera Beacon`, `Flexera Importers` and `Flexera Package Repository` for specific central-server roles and communication paths.

This is important because the existence of an AppPool named `Flexera Beacon` does **not** prove that it is the worker process serving downstream Inventory Agent uploads/downloads on every standalone Beacon.

### Monitoring implication

The project must continue to discover the AppPool by resolving the actual `ManageSoftRL` / `ManageSoftDL` IIS topology rather than selecting an AppPool solely by name.

Known Flexera AppPool names may be used as hints and reported as metadata.

Reference:

- https://docs.flexera.com/fnms/inventory-beacon-overview/fib-ref-introduction/iis-application-pools

---

## 11. AppPool identity and service-account failures

Flexera documents IIS Application Pools as potentially running under service accounts and documents expired/invalid pool credentials as a cause of stopped pools.

### Monitoring implication

The collector may record:

- AppPool state.
- identity type.
- account name only when safe and useful.
- WAS/IIS events that explain a pool failing to start.

Do not collect credentials.

If account names are persisted, provide a way to suppress/redact them in exported reports.

References:

- https://docs.flexera.com/fnms-install/installation-guide/prerequisites-and-preparations/accounts
- https://docs.flexera.com/fnms-install/installation-guide/notes-on-issues/identifying-iis-application-pool-credential-issues/update-credentials-in-iis-application-pools

---

## 12. Security hardening recommendation: HTTP SERVER header

Flexera's Inventory Beacon best-practices documentation notes that the Beacon removes the `SERVER` header from most HTTP responses, while malformed URLs handled directly by HTTP.sys can still expose `Microsoft-HTTPAPI/2.0` unless the Windows HTTP service is configured otherwise.

This is a **security/hardening recommendation**, not a performance requirement.

### Monitoring implication

For v0.1 this should be informational only. The collector may optionally report whether the documented `DisableServerHeader` HTTP.sys registry setting is present.

It must never change this registry value because the setting affects all IIS/HTTP.sys applications on the server and requires an HTTP service/server restart to take effect.

Reference:

- https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/best-practices-for-inventory-beacon

---

## 13. No Flexera-specific performance thresholds found

The reviewed Flexera documentation specifies prerequisites, supported topology, authentication, protocols and configuration behavior, but does not define general IIS performance limits such as:

- maximum acceptable CPU percentage.
- maximum `w3wp.exe` memory usage.
- maximum request rate.
- universal P95/P99 response-time thresholds.
- a universal acceptable HTTP.sys queue depth.

Therefore `iis-flexera` must not present internally chosen thresholds as official Flexera limits.

### Reporting rule

Prefer evidence such as:

```text
P95 worker CPU: 24.2%
Maximum worker CPU: 67.8%
P95 request latency: 182 ms
Maximum HTTP.sys queue depth: 0
Rejected requests: 0
```

If project-specific heuristics are later introduced, label them explicitly as **iis-flexera heuristics**, separate from Flexera requirements/recommendations.

---

## 14. New configuration-baseline output

The implementation should add a read-only configuration snapshot to each collection run:

```text
configuration-baseline.json
```

Suggested conceptual structure:

```json
{
  "flexeraBaselineVersion": 1,
  "iis": {
    "version": null,
    "httpLoggingInstalled": null,
    "webDav": null,
    "staticCompressionInstalled": null,
    "dynamicCompressionInstalled": null,
    "requestFilteringInstalled": null
  },
  "sites": [],
  "endpoints": [
    {
      "name": "ManageSoftRL",
      "site": null,
      "appPool": null,
      "authentication": {},
      "requestFiltering": {},
      "bindings": []
    },
    {
      "name": "ManageSoftDL",
      "site": null,
      "appPool": null,
      "authentication": {},
      "requestFiltering": {},
      "bindings": []
    }
  ],
  "warnings": []
}
```

This baseline is captured once at startup and, optionally, again at the end of the seven-day run to identify configuration drift.

#### Implementation status (iis-flexera v0.1)

`New-FlexeraConfigurationBaseline` (`src/ConfigurationBaseline.ps1`) implements this with two additions beyond the sketch above, each documented in the sections that motivate them (7 and 3.1):

```json
{
  "Logging": [
    { "SiteName": null, "Enabled": null, "LogFormat": null, "Directory": null, "EnabledFields": [], "MissingFields": [ { "Field": null, "Impact": null } ], "AllRequiredFieldsPresent": null }
  ],
  "AuthenticationConsistency": [
    { "ControlId": "FB-IIS-BASE-001", "Status": null, "ObservedValue": null, "EffectiveRecommendation": null }
  ]
}
```

Each `Endpoints[]` entry also carries `PhysicalPath` (used to infer topology for the authentication-consistency check) and `Authentication` (`AnonymousEnabled`/`BasicEnabled`/`WindowsEnabled`, each `$null` when unreadable). `bindings` per endpoint is not yet populated; binding/certificate data currently lives only on `Sites[].Bindings` in `metadata.json`.

---

## 15. Implementation priority changes

The Flexera baseline adds a **preflight phase** before performance sampling:

1. Confirm IIS is present and active for the selected Beacon web path.
2. Discover `ManageSoftRL` / `ManageSoftDL` and resolve their effective IIS topology.
3. Capture required IIS role-service presence.
4. Capture bindings/protocols.
5. Capture effective authentication.
6. Check WebDAV state.
7. Inspect Request Filtering for known Flexera extensions when applicable.
8. Validate logging availability and fields.
9. Resolve AppPool(s) and worker PID(s).
10. Start performance sampling.

A failed compliance/preflight check should normally produce a warning rather than prevent monitoring, unless the topology is ambiguous enough that the collector cannot reliably attribute data to the Flexera IIS workload.

---

## 16. Reference set

Primary Flexera references used for this baseline:

- Prerequisites for Inventory Beacons  
  https://docs.flexera.com/flexera-one/it-assets/inventory-beacon/prerequisites-for-inventory-beacons

- Configuring Inventory Collection — Flexera One  
  https://docs.flexera.com/flexera/EN/ITAssets/ConfiguringDirectInvGathering.htm

- Configuring Inventory Collection — FlexNet Manager Suite  
  https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection

- Adjusting the Web Server on the Inventory Beacon  
  https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/adjusting-the-web-server-on-the-inventory-beacon

- IIS Application Pools  
  https://docs.flexera.com/fnms/inventory-beacon-overview/fib-ref-introduction/iis-application-pools

- Configure .NET and IIS / WebDAV guidance  
  https://docs.flexera.com/fnms-install/upgrade-guide/prerequisites-and-preparations/configure-net-and-iis

- Recommended Best Practices for the Inventory Beacon  
  https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/best-practices-for-inventory-beacon

- Configuring Mutual TLS  
  https://docs.flexera.com/FlexNetManagerSuite2022R1/EN/WebHelp/tasks/ConfigureMutualTLS.html

- Accounts / IIS Application Pool service accounts  
  https://docs.flexera.com/fnms-install/installation-guide/prerequisites-and-preparations/accounts

Because Flexera documentation evolves, implementation and future releases should revalidate these assumptions against the supported Flexera version rather than treating this file as a substitute for vendor documentation.
