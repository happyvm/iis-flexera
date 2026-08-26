# Flexera Beacon IIS Security Audit

## 1. Purpose

This document defines the security-assessment component of `iis-flexera`.

The objective is not to apply generic IIS hardening blindly. The objective is to compare the **observed configuration** of the IIS workload used by a Flexera Inventory Beacon against two reference sets:

1. Microsoft IIS security guidance.
2. Flexera Inventory Beacon requirements and recommendations.

The audit must then produce an **effective recommendation that remains compatible with Flexera**.

The collector remains read-only. It must never remediate a security finding automatically.

---

## 2. Why a three-way comparison is required

A generic IIS hardening recommendation can be incomplete or even inappropriate for a Flexera Beacon.

Examples:

- Microsoft recommends minimizing the installed/active IIS surface area, but Flexera requires specific IIS role services and handlers.
- Microsoft recommends authenticating users before allowing uploads; Flexera recommends anonymous authentication where possible for inventory-agent communications because it simplifies failover and avoids orphaning agents after credential changes.
- Microsoft Request Filtering is a valuable security feature; Flexera requires that filters do not block extensions used by the FlexNet Inventory Agent, including `.osd`, `.npl`, `.nds`, and `.ini`.
- WebDAV may be useful in some IIS publishing scenarios, but Flexera explicitly requires WebDAV to be disabled on IIS-based Inventory Beacons because it can intercept HTTP processing and block inventory functionality.

For this reason, the audit must never report a simple generic “IIS compliant/non-compliant” result without considering Flexera compatibility.

---

## 3. Source hierarchy

The audit uses three evidence classes.

### 3.1 Observed configuration

What is actually configured on the server, site, application, virtual directory, Application Pool, HTTP.sys/SSL binding, certificate store and relevant Flexera web configuration.

This is the factual baseline.

### 3.2 Microsoft IIS guidance

Microsoft guidance is used for generic IIS security posture, including:

- minimizing installed/active modules,
- application isolation,
- low-privilege Application Pool identities,
- Request Filtering,
- authentication security,
- TLS/HTTPS,
- HSTS where applicable,
- directory browsing,
- logging.

Microsoft guidance must not be presented as a Flexera product requirement.

### 3.3 Flexera guidance

Flexera guidance is authoritative for product compatibility and Beacon-specific security behavior.

Flexera guidance must be classified as one of:

- `FLEXERA_REQUIRED` — documented as required/must.
- `FLEXERA_RECOMMENDED` — explicitly recommended/preferred by Flexera.
- `FLEXERA_OPTIONAL_SECURITY` — supported security enhancement, such as mutual TLS.
- `FLEXERA_COMPATIBILITY` — behavior or limitation that constrains generic IIS hardening.

Do not promote an optional Flexera capability to a mandatory requirement.

---

## 4. Assessment statuses

Each control must return one of these statuses:

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

Definitions:

- `PASS`: observed configuration matches the effective recommendation.
- `FAIL`: clear documented security or Flexera requirement is not met.
- `WARNING`: improvement is recommended but the finding is not an explicit product-breaking requirement.
- `INFO`: observation only.
- `NOT_APPLICABLE`: control does not apply to the detected topology/version.
- `UNKNOWN`: insufficient evidence to decide.
- `FLEXERA_EXCEPTION`: a generic IIS recommendation must be adjusted because of a documented Flexera requirement or compatibility constraint.
- `CONFLICT`: Microsoft and Flexera guidance appear incompatible and no safe automatic interpretation can be made.

The report must explain every `FLEXERA_EXCEPTION` and `CONFLICT` rather than hiding them in a score.

---

## 5. No single security score in v0.1

Do not generate a single percentage such as “Beacon security score: 82%” in version 0.1.

Such a score would be misleading because:

- some Microsoft recommendations are contextual,
- some Flexera requirements intentionally constrain generic hardening,
- some controls are optional enhancements,
- control severity is environment-dependent.

Instead report counts by status and category.

Example:

```text
Flexera requirements       12 PASS / 1 FAIL / 1 UNKNOWN
Microsoft IIS guidance     18 PASS / 4 WARNING
Compatibility exceptions    2 FLEXERA_EXCEPTION
Optional enhancements       3 INFO
```

---

## 6. Output files

The monitoring run should add:

```text
configuration-baseline.json
security-audit.json
security-audit.csv
```

The final `report.md` must include a security section that summarizes the audit.

### 6.1 Suggested security-audit schema

Each control should preserve at least:

```text
ControlId
Category
Scope
ObservedValue
MicrosoftGuidance
FlexeraGuidance
EffectiveRecommendation
Status
Priority
Evidence
MicrosoftSource
FlexeraSource
Notes
```

`Priority` is a project triage value, not a Microsoft or Flexera severity rating unless the vendor explicitly assigns one.

**Implementation status (iis-flexera v0.1):** `ControlId`, `Category`, `Scope`, `ObservedValue`, `MicrosoftGuidance`, `FlexeraGuidance`, `EffectiveRecommendation`, `Status` and `Priority` are implemented (`src/SecurityAudit.ps1`). `Evidence`, `MicrosoftSource` and `FlexeraSource` (as structured fields separate from the guidance text) and `Notes` are not yet implemented. `Scope` matters in practice: a standalone Beacon's `ManageSoftRL` and `ManageSoftDL` share one directory/web.config, so several controls (WebDAV, Request Filtering, Basic/Anonymous authentication) are evaluated once per endpoint and legitimately produce two findings with identical `ObservedValue`/`Status` but different `Scope` (e.g. `Default Web Site/ManageSoftRL` vs `Default Web Site/ManageSoftDL`) - this is intentional per-endpoint evidence, not a duplicate-emission bug, and `Scope` is what makes that visible instead of the two rows looking like an accidental copy.

Suggested values:

```text
Critical
High
Medium
Low
Informational
```

---

## 7. Initial control catalogue

The following controls define the initial implementation target.

`FLEXERA-IIS-BASELINE.md` section 3.1 defines one additional finding outside this catalogue's numbering, `FB-IIS-BASE-001` (authentication consistency between `ManageSoftRL`/`ManageSoftDL` on a standalone Beacon), reported alongside these controls in `configuration-baseline.json`'s `AuthenticationConsistency` array and merged into `security-audit.json`/the report's security section for visibility.

### FB-IIS-SEC-001 — HTTPS use

**Observed:**

- IIS bindings.
- Flexera-advertised protocol where readable.
- requests observed over HTTP vs HTTPS if attributable.

**Flexera guidance:**

Flexera states that, in general, the preferred first step for increasing Inventory Beacon security is to configure the Beacon for HTTPS. Basic Authentication should be reserved for cases where it is considered critical.

**Effective recommendation:**

Prefer HTTPS for Beacon-agent communications.

Status guidance:

- HTTPS active and used: `PASS`.
- HTTP only: `WARNING` unless an explicit environment policy requires stronger treatment.
- Flexera configuration advertises HTTPS but IIS does not provide a usable HTTPS binding: `FAIL`.

Source:

https://docs.flexera.com/fnms/inventory-beacon/prerequisites-for-inventory-beacons

---

### FB-IIS-SEC-002 — Standard IIS ports for Beacon-agent communications

**Observed:** IIS HTTP/HTTPS bindings.

**Flexera guidance:**

For the IIS web server mode, current Flexera documentation states that target devices recognize the standard ports:

```text
HTTP  -> 80
HTTPS -> 443
```

This differs from Flexera's self-hosted web server, whose port is configurable.

**Effective recommendation:**

Do not treat a custom IIS port as equivalent to the documented Flexera IIS configuration without explicit validation for the deployed product/version.

- 80 for HTTP or 443 for HTTPS: `PASS` for this control.
- custom IIS port used for Beacon-agent communication: `WARNING` or `UNKNOWN`, with a compatibility note.

Source:

https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection

---

### FB-IIS-SEC-003 — TLS server certificate

**Observed for HTTPS binding:**

- certificate thumbprint,
- certificate subject/SAN,
- DNS name used for Beacon communication,
- validity period,
- certificate expiry,
- certificate chain status where locally verifiable,
- private-key availability,
- certificate bound to the HTTPS endpoint.

**Flexera guidance:**

For TLS, Flexera expects the client to validate the Beacon server certificate. The server certificate must be valid and trusted by the client, and its DNS identity must match the server being contacted.

**Effective recommendation:**

Flag expired, not-yet-valid, name-mismatched or locally untrusted certificates. Do not assume that local trust proves all remote Inventory Agents trust the issuing CA.

Sources:

https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-mutual-tls

https://docs.flexera.com/fnms-discovery/gathering-flexnet-inventory/flexnet-inventory-agent/3rd-party-deployment/implementation/unix-config/install-unix/agent-third-party-deployment-enabling-https-protocol-on-unix-agents

**Implementation status (iis-flexera v0.1):** implemented as two findings sharing this control ID (`src/SecurityAudit.ps1`): `Get-CertificateValidityControl` (`NotBefore`/`NotAfter` vs. the current time, `WARNING` inside a 30-day expiry window, `FAIL` if expired or not yet valid) and `Get-CertificateNameMatchControl` (expected host from the binding vs. the certificate's CN/SAN, with one-label wildcard matching, e.g. `*.example.com`). Certificate metadata is read via `Get-SslCertificateInfo` (`src/Discovery.ps1`) from the local machine certificate store by thumbprint, without exporting the private key (only a `HasPrivateKey` boolean is reported). Certificate **chain**/trust validation is not implemented.

---

### FB-IIS-SEC-004 — Server-certificate validation preference

**Observed where safely readable:**

Flexera `CheckServerCertificate` preference.

**Flexera guidance:**

Flexera documents `CheckServerCertificate=True` as the default behavior so components validate the Inventory Beacon server certificate against a trusted root CA.

**Effective recommendation:**

- missing preference when documented default applies: record effective value `True` and `PASS`.
- explicitly `True`: `PASS`.
- explicitly `False`: `FAIL` or high-priority `WARNING`, with clear security rationale.

Source:

https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/registry-keys-for-inventory-beacon

**Implementation status (iis-flexera v0.1):** not implemented. The cited source names a Flexera registry key for this preference but does not give its exact path in the documentation reviewed for this project, and guessing one risks reading the wrong value and reporting fabricated evidence (see `AGENTS.md`, "never fabricate unavailable measurements"). Implement this once the exact registry key path is confirmed against the deployed Flexera release.

---

### FB-IIS-SEC-005 — Certificate revocation checking

**Observed where safely readable:**

Flexera `CheckCertificateRevocation` preference and relevant connectivity evidence if practical.

**Flexera guidance:**

Flexera documents certificate revocation checking as enabled by default and explicitly states that disabling it is for emergency use only and introduces an unacceptable security weakness in most operational environments.

**Effective recommendation:**

- absent/default or `True`: `PASS`.
- `False`: `FAIL` or high-priority `WARNING` with the exact reason recorded.

Do not attempt a configuration change.

Sources:

https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/registry-keys-for-inventory-beacon

https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/configuring-for-proxy-servers

**Implementation status (iis-flexera v0.1):** not implemented, for the same reason as FB-IIS-SEC-004 (exact registry key path not confirmed).

---

### FB-IIS-SEC-006 — Basic Authentication over HTTPS only

**Observed:**

- Basic Authentication state at server/site/application/path scope,
- Anonymous Authentication state,
- HTTPS binding,
- SSL requirement where configured.

**Microsoft guidance:**

IIS Basic Authentication transmits usernames and passwords in an unencrypted form unless transport encryption such as SSL/TLS is used.

**Flexera guidance:**

Flexera supports Basic Authentication but generally prefers anonymous access where possible and recommends HTTPS as the first security improvement.

**Effective recommendation:**

- Basic Authentication enabled while effective client traffic can use HTTP: `FAIL`.
- Basic Authentication enabled and HTTPS enforced: `PASS` with a note that Flexera operational implications must be considered.
- Basic Authentication disabled: not automatically better or worse; evaluate the effective Flexera authentication model.

Microsoft source:

https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/basicauthentication

Flexera sources:

https://docs.flexera.com/fnms/inventory-beacon/prerequisites-for-inventory-beacons

https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/changing-iis-passwords-on-inventory-beacons

**Implementation status (iis-flexera v0.1):** implemented as `Get-BasicAuthenticationControl` (`src/SecurityAudit.ps1`), wired per Flexera endpoint using effective authentication read via `Get-IisAuthenticationState` and whether the endpoint's site has an HTTPS binding. "Basic Authentication disabled" resolves to `NOT_APPLICABLE` rather than a further evaluation of the authentication model, which remains a manual judgment call for now.

---

### FB-IIS-SEC-007 — Anonymous Authentication compatibility

**Observed:** Anonymous Authentication state on Flexera endpoints.

**Microsoft generic guidance:**

Microsoft IIS security guidance recommends authenticating users before allowing uploads.

**Flexera guidance:**

Flexera explicitly recommends anonymous IIS authentication wherever possible for Inventory Beacons because Inventory Agents initiate communication and failover behavior depends on agents being able to reach alternate Beacons without possessing credentials for each one.

Flexera also warns that changing Basic Authentication credentials incorrectly can leave managed devices orphaned.

**Effective recommendation:**

This is a documented product-specific security trade-off.

Do not report anonymous authentication as a generic failure solely because an upload endpoint exists.

Instead:

- anonymous + HTTPS: normally `PASS` for Flexera compatibility, with security context documented.
- anonymous + HTTP: `WARNING` because communications are unencrypted.
- Basic/other authentication: evaluate against the intended Flexera topology and failover design.
- mutual TLS: treat as a stronger optional client-authentication design when correctly deployed.

This control may produce `FLEXERA_EXCEPTION` relative to generic IIS guidance.

Microsoft source:

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj635855(v=ws.11)

Flexera sources:

https://docs.flexera.com/fnms/inventory-beacon/prerequisites-for-inventory-beacons

https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/changing-iis-passwords-on-inventory-beacons

**Implementation status (iis-flexera v0.1):** implemented as `Get-AnonymousAuthenticationControl` (`src/SecurityAudit.ps1`), wired the same way as FB-IIS-SEC-006. "Basic/other authentication: evaluate against topology/failover design" and the mutual-TLS cross-reference remain manual judgment calls; only the anonymous+HTTPS/anonymous+HTTP cases are automated.

---

### FB-IIS-SEC-008 — Mutual TLS

**Observed:**

- HTTPS present,
- SSL required,
- client certificate mode (`Ignore`, `Accept`, `Require`),
- Flexera mutual-TLS-related configuration where safely readable.

**Flexera guidance:**

Flexera supports mutual TLS for Beacon-agent communication. When configured to require a client certificate, every participating Inventory Agent that may contact that Beacon must be prepared to present one.

Flexera notes an important limitation: the Beacon validates client-certificate format and validity period but does not perform certificate revocation checking on the client certificate.

**Effective recommendation:**

mTLS is an optional enhanced-security profile, not a mandatory baseline.

- correctly configured mTLS: `INFO` or `PASS` under an enhanced-security profile.
- partially configured mTLS: `WARNING`/`FAIL` depending on whether communications are broken.
- no mTLS: `NOT_APPLICABLE` under the default baseline.

Source:

https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-mutual-tls

**Implementation status (iis-flexera v0.1):** implemented as `Get-MutualTlsControl` (`src/SecurityAudit.ps1`). The client-certificate mode is decoded from the binding's `sslFlags` bitmask via `Get-ClientCertificateMode`. `Require` over HTTPS reports `INFO` (not `PASS` - mTLS correctness cannot be confirmed from server-side configuration alone); `Require` without HTTPS reports `FAIL`; `Ignore` reports `NOT_APPLICABLE`. "Partially configured" beyond the Require-without-HTTPS case is not distinguished further.

---

### FB-IIS-SEC-009 — WebDAV disabled

**Observed:**

- WebDAV role/module installation,
- WebDAV module active state,
- authoring-rule state on selected Flexera site/applications.

**Flexera guidance:**

Flexera explicitly requires WebDAV to be disabled for IIS-based Inventory Beacons because it can intercept HTTP processing and block FlexNet inventory functionality.

**Effective recommendation:**

WebDAV active for the relevant Flexera site/path: `FAIL`.

WebDAV absent or disabled: `PASS`.

Source:

https://docs.flexera.com/fnms-install/upgrade-guide/prerequisites-and-preparations/configure-net-and-iis

---

### FB-IIS-SEC-010 — Request Filtering enabled and Flexera-compatible

**Observed:**

- Request Filtering role/module availability,
- effective configuration at server/site/application/path scopes,
- extension rules,
- verb rules,
- hidden segments,
- denied URL sequences,
- request limits,
- `allowDoubleEscaping`,
- other relevant requestFiltering values.

**Microsoft guidance:**

Request Filtering is an IIS security feature intended to reject unwanted or potentially harmful requests.

**Flexera guidance:**

Flexera requires that filtering not block file extensions used by the Inventory Agent, explicitly including:

```text
.osd
.npl
.nds
.ini
```

Depending on Flexera product/version, Request Filtering is either listed as an IIS role service used by the product or documented as an optional feature that must be configured compatibly.

**Effective recommendation:**

Enable/use Request Filtering when compatible, but never propose a rule that blocks known Flexera payload types.

Possible results:

- enabled and Flexera-required extensions work: `PASS`.
- disabled: `WARNING` under Microsoft hardening unless the detected product/version provides a documented reason.
- enabled but required Flexera extensions are denied: `FAIL` for compatibility.

Microsoft sources:

https://learn.microsoft.com/en-us/iis/manage/configuring-security/configure-request-filtering-in-iis

https://learn.microsoft.com/en-us/iis/configuration/system.webServer/security/requestFiltering/

Flexera sources:

https://docs.flexera.com/fnms/inventory-beacon/prerequisites-for-inventory-beacons

https://docs.flexera.com/fnms-install/installation-guide/notes-on-issues/iis-roles-services

---

### FB-IIS-SEC-011 — Required IIS role services

**Observed:** Windows IIS role services/features and corresponding modules.

**Flexera guidance:**

Depending on deployed Flexera topology/version, Flexera documents IIS role services used by Inventory Beacons, including items such as:

- .NET Extensibility,
- ASP.NET,
- CGI,
- ISAPI Extensions,
- ISAPI Filters,
- Default Document,
- Directory Browsing role service,
- HTTP Errors,
- HTTP Redirection,
- Static Content,
- HTTP Logging,
- Dynamic Content Compression,
- Static Content Compression,
- Basic Authentication,
- Request Filtering,
- Windows Authentication.

**Important interpretation rule:**

An IIS role service being installed does not necessarily mean the feature should be enabled at every site/path.

Example: Microsoft recommends leaving **directory browsing disabled** unless it is needed. Flexera may require the Directory Browsing role service/module to be available as part of its supported IIS feature set, while the effective site-level `directoryBrowse.enabled` value can still be `false`.

The audit must distinguish:

```text
Windows role service installed
IIS module available
IIS feature enabled at server level
IIS feature enabled at site/application/path level
```

Do not collapse these into one boolean.

Microsoft source:

https://learn.microsoft.com/en-us/iis/wmi-provider/directorybrowsesection-class

Flexera source:

https://docs.flexera.com/fnms-install/installation-guide/notes-on-issues/iis-roles-services

---

### FB-IIS-SEC-012 — Directory browsing effective state

**Observed:** effective `system.webServer/directoryBrowse` state on Flexera paths.

**Microsoft guidance:**

Directory browsing is disabled by default and Microsoft recommends leaving it disabled unless there is a specific requirement.

**Effective recommendation:**

- role/module installed but site/path browsing disabled: `PASS`.
- directory browsing enabled on a Flexera endpoint without a documented functional need: `WARNING`.
- if a detected Flexera version explicitly requires site-level browsing, classify as `FLEXERA_EXCEPTION` and document evidence.

Source:

https://learn.microsoft.com/en-us/iis/wmi-provider/directorybrowsesection-class

---

### FB-IIS-SEC-013 — Application Pool identity

**Observed:**

- Application Pool identity type,
- username where applicable,
- `loadUserProfile`,
- pool isolation/topology,
- whether multiple unrelated applications share the pool.

Never export account passwords or secrets.

**Microsoft guidance:**

Microsoft recommends low-privilege and isolated Application Pool identities. `ApplicationPoolIdentity` provides a unique virtual identity for each pool on supported Windows versions.

**Effective recommendation:**

- unique low-privilege AppPool identity: `PASS`.
- LocalSystem/highly privileged identity: `FAIL` or high-priority `WARNING` unless Flexera explicitly documents a requirement.
- shared identity/pool across unrelated applications: `WARNING` depending on topology.

Source:

https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities

---

### FB-IIS-SEC-014 — Minimize IIS module/handler surface

**Observed:**

- installed IIS role services,
- global modules,
- effective modules for selected Flexera applications,
- handler mappings.

**Microsoft guidance:**

Install only required IIS modules and periodically remove unused modules/handlers to reduce attack surface.

**Flexera compatibility rule:**

Never recommend removal solely because a module appears unused during the seven-day monitoring period. Some Flexera functionality may be infrequent.

Compare installed modules against the documented Flexera role-service baseline and classify extras as `INFO`/`WARNING` candidates for review, not automatic failures.

Sources:

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj635855(v=ws.11)

https://docs.flexera.com/fnms-install/installation-guide/notes-on-issues/iis-roles-services

---

### FB-IIS-SEC-015 — HTTP Logging

**Observed:**

- HTTP Logging role/module,
- site logging enabled,
- log format,
- configured fields,
- log path,
- rollover settings.

**Flexera guidance:** HTTP Logging is part of the documented IIS prerequisites/roles used by Inventory Beacons.

**Project requirement:** logging is also required for the performance/security analyzer to explain HTTP behavior.

- logging disabled: `FAIL` for audit observability and potentially Flexera baseline compliance.
- logging enabled but missing security/performance fields: `WARNING`.

Sources:

https://docs.flexera.com/fnms/inventory-beacon/prerequisites-for-inventory-beacons

https://docs.flexera.com/fnms-install/installation-guide/notes-on-issues/iis-roles-services

**Implementation status (iis-flexera v0.1):** implemented as `Get-HttpLoggingControl` (`src/SecurityAudit.ps1`), wired per site using `Get-IisLoggingConfiguration`/`Test-RequiredW3CFieldsPresent` from `src/ConfigurationBaseline.ps1` (see section 7 of `FLEXERA-IIS-BASELINE.md`). "Missing security/performance fields" is currently checked for `time-taken` specifically rather than the full required-field list; the full list's impact is still reported separately in `configuration-baseline.json`'s `Logging[].MissingFields`. When the effective logging state cannot be read at all, the control reports `UNKNOWN` rather than guessing `FAIL`/`PASS`.

---

### FB-IIS-SEC-016 — TLS protocol posture

**Observed where possible without intrusive probing:**

- Schannel protocol configuration,
- IIS/HTTP.sys TLS binding context,
- OS version,
- certificate properties.

**Flexera guidance:**

Current Flexera cloud system requirements document TLS 1.2 for communication between Inventory Beacons and the application server. This is not automatically equivalent to a statement that every Beacon-agent IIS endpoint must reject every older TLS version.

**Effective recommendation:**

Report protocol posture separately from product compatibility.

Do not disable TLS 1.0/1.1 automatically and do not claim that Flexera requires their removal from the Beacon-agent IIS endpoint unless documentation for the deployed version explicitly says so.

The audit may flag legacy protocols as Microsoft/security hardening concerns while preserving a `compatibility review required` note.

Flexera source:

https://docs.flexera.com/fnms/EN/WebHelp/PDF%20Documents/Cloud/ITAMSystemRequirementsCloud%20Edition.pdf

---

### FB-IIS-SEC-017 — HSTS

**Observed:** IIS site HSTS configuration where supported.

**Microsoft guidance:**

IIS 10.0 version 1709 and later can natively configure HSTS. HSTS strengthens HTTPS use for browser clients.

**Flexera compatibility note:**

Inventory Agents are not web browsers. Do not assume HSTS materially improves agent-to-Beacon security. Treat it as contextual web-server hardening, not a Flexera requirement.

- HTTPS + HSTS enabled: `INFO`/`PASS` for Microsoft web hardening.
- HSTS absent: normally `INFO`, not a Flexera failure.

Source:

https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10-version-1709/iis-10-version-1709-hsts

---

### FB-IIS-SEC-018 — Configuration inheritance and effective values

IIS security settings can be inherited and overridden at several levels.

The audit must capture the **effective value** for the selected Flexera endpoint, while preserving enough provenance to explain where that value came from.

At minimum consider:

```text
server
site
application
virtual directory/path
web.config location override
```

A server-level setting alone is insufficient if a lower-level override changes the effective configuration.

---

## 8. Authentication decision matrix

The report should summarize the effective Flexera-facing authentication model.

| Protocol | Anonymous | Basic | Client certificate | Assessment |
|---|---:|---:|---:|---|
| HTTP | Yes | No | No | Flexera-compatible but unencrypted; security warning |
| HTTPS | Yes | No | No | Flexera-preferred general model with transport encryption |
| HTTP | No | Yes | No | Unsafe Basic Authentication; fail |
| HTTPS | No | Yes | No | Supported; review operational/failover implications |
| HTTPS | varies | varies | Required | Flexera-supported enhanced mTLS design |

This table is conceptual. The implementation must evaluate actual inherited IIS settings and the detected Flexera topology.

---

## 9. Flexera-compatible hardening principle

The tool should output three columns conceptually:

```text
CURRENT CONFIGURATION
MICROSOFT IIS GUIDANCE
FLEXERA GUIDANCE
```

and then derive:

```text
EFFECTIVE RECOMMENDATION
```

Example:

```text
Control: Anonymous authentication on ManageSoftRL

Current:
  Enabled

Microsoft generic IIS guidance:
  Authenticate before permitting uploads.

Flexera guidance:
  Anonymous authentication is preferred where possible for Inventory Beacons
  because of agent-initiated communications and failover behavior.

Effective assessment:
  FLEXERA_EXCEPTION / PASS for product-compatible baseline
  Recommendation: keep anonymous if required by the current Flexera design,
  but use HTTPS; consider mTLS if stronger client authentication is required.
```

This is the central design principle of the security audit.

---

## 10. Configuration data to collect

The read-only preflight should collect at least:

### IIS server/features

- IIS version.
- Installed IIS role services.
- Global/effective modules.
- Handler mappings relevant to Flexera applications.
- WebDAV state.
- Request Filtering state.
- HTTP Logging state.
- Directory Browsing state.

### Sites/applications

- site/application/path hierarchy,
- bindings,
- authentication settings,
- SSL requirements,
- Request Filtering effective configuration,
- logging configuration,
- HSTS where supported,
- relevant response headers if statically configured.

### Application Pools

- pool identity type,
- pipeline mode,
- runtime version,
- worker process count,
- queue length,
- start mode,
- recycle configuration,
- current PIDs.

Security reporting should focus on identity/isolation. Performance reporting may use the remaining values.

### TLS/certificates

- HTTP/HTTPS binding,
- certificate thumbprint,
- subject/SAN,
- issuer,
- validity dates,
- local chain result where practical,
- client certificate mode,
- effective SSL flags.

### Relevant Flexera settings

Read only values necessary to interpret the web-security design, including where available:

- advertised protocol,
- authentication mode,
- `CheckServerCertificate`,
- `CheckCertificateRevocation`,
- mutual TLS-related web settings,
- allowed/download extensions relevant to Request Filtering.

Do not collect secret credentials.

---

## 11. Secrets and sensitive information

The security audit must never write the following to output:

- Basic Authentication passwords,
- private keys,
- certificate private-key material,
- stored Flexera credentials,
- secrets from configuration files,
- authorization headers,
- cookies,
- full query strings containing sensitive tokens.

Usernames should be minimized. If an account identity is needed for AppPool analysis, output only the account name and never credentials.

---

## 12. Read-only rule

The audit must never automatically:

- enable HTTPS,
- add/remove bindings,
- replace certificates,
- change TLS protocols,
- enable HSTS,
- alter authentication,
- enable/disable WebDAV,
- change Request Filtering,
- add/remove IIS role services,
- alter AppPool identity,
- change registry preferences,
- change Flexera configuration.

Future remediation functionality, if ever added, must be a separate explicit opt-in mode and must not be part of the v0.1 monitor.

---

## 13. Report layout

The final Markdown report should include:

```text
Security configuration assessment

1. Summary
2. Flexera mandatory requirements
3. Flexera recommendations
4. Microsoft IIS hardening observations
5. Flexera compatibility exceptions
6. TLS and certificate posture
7. Authentication model
8. Request Filtering / WebDAV
9. Application Pool isolation
10. Logging / auditability
11. Unknown or unverified controls
12. Recommended manual actions
```

Example table:

| Control | Current | Microsoft | Flexera | Effective status |
|---|---|---|---|---|
| HTTPS | Enabled/443 | Prefer HTTPS | Preferred first security step | PASS |
| Basic Auth | Disabled | Avoid plaintext credentials | Anonymous preferred where possible | PASS |
| WebDAV | Disabled | Minimize unused surface | Must be disabled for Beacon IIS | PASS |
| Request Filtering | Enabled | Recommended | Must allow Flexera extensions | PASS |
| Directory browsing | Disabled at site | Keep disabled unless needed | Role service may be installed | PASS |
| mTLS | Not configured | Contextual | Supported optional enhancement | INFO |

---

## 14. Version awareness

Flexera documentation changes over time.

The report must record:

- detected Flexera Beacon version where available,
- Windows Server version,
- IIS version,
- audit-rule-set version,
- date/version of the Flexera baseline embedded in the tool.

Rules that are known to be version-specific must not be applied blindly to another version.

If the Beacon version cannot be determined, report this and use conservative wording such as:

```text
Guidance based on the current documented Flexera Inventory Beacon baseline;
verify against documentation for the installed Flexera release.
```

---

## 15. Acceptance criteria for the security component

The security component is acceptable when:

1. It discovers the effective IIS configuration for the selected Flexera endpoints.
2. It reports current configuration separately from Microsoft and Flexera guidance.
3. It distinguishes Flexera requirements from optional security features.
4. It can represent a Flexera compatibility exception without marking it as a generic hardening failure.
5. It validates HTTPS bindings and certificate metadata without exporting secrets.
6. It detects Basic Authentication over unencrypted HTTP.
7. It detects WebDAV enabled on relevant Flexera IIS paths.
8. It validates Request Filtering without recommending rules that block Flexera-required extensions.
9. It distinguishes role-service installation from site-level feature enablement.
10. It evaluates AppPool identity/isolation.
11. It records unknown/unverifiable controls explicitly.
12. It produces `security-audit.json` and a readable Markdown summary.
13. It makes no configuration changes.

---

## 16. Primary references

### Flexera

- Inventory Beacon prerequisites and authentication guidance:
  https://docs.flexera.com/fnms/inventory-beacon/prerequisites-for-inventory-beacons

- Configuring Inventory Collection / IIS versus self-hosted behavior:
  https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection

- Mutual TLS:
  https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-mutual-tls

- Changing IIS passwords / Basic Authentication operational impact:
  https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/changing-iis-passwords-on-inventory-beacons

- Registry keys / certificate checking:
  https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/registry-keys-for-inventory-beacon

- Proxy / revocation-check guidance:
  https://docs.flexera.com/flexera-one/it-assets/inventory-beacon-overview/fib-ref-introduction/configuring-for-proxy-servers

- Configure .NET/IIS and disable WebDAV:
  https://docs.flexera.com/fnms-install/upgrade-guide/prerequisites-and-preparations/configure-net-and-iis

- IIS roles/services used by Flexera:
  https://docs.flexera.com/fnms-install/installation-guide/notes-on-issues/iis-roles-services

### Microsoft

- IIS security best practices:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj635855(v=ws.11)

- Request Filtering:
  https://learn.microsoft.com/en-us/iis/manage/configuring-security/configure-request-filtering-in-iis

- Basic Authentication:
  https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/basicauthentication

- Application Pool identities:
  https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities

- Directory browsing:
  https://learn.microsoft.com/en-us/iis/wmi-provider/directorybrowsesection-class

- HSTS:
  https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10-version-1709/iis-10-version-1709-hsts
