# Read-only Microsoft-vs-Flexera IIS security audit.
#
# Every control below is a pure decision function: given observed values,
# it returns a status from the model in SECURITY-AUDIT.md section 4. This
# keeps the compatibility logic (e.g. why anonymous authentication is a
# FLEXERA_EXCEPTION rather than a generic failure) independently testable
# without needing a live IIS host.
#
# v0.1 scope note: this file implements a subset of the full control
# catalogue in SECURITY-AUDIT.md section 7 (HTTPS, port, TLS certificate
# validity/name match, mutual TLS, Basic/Anonymous authentication, WebDAV,
# Request Filtering, directory browsing, AppPool identity, HTTP logging)
# plus the Flexera-specific authentication-consistency check from
# FLEXERA-IIS-BASELINE.md section 3.1. FB-IIS-SEC-004/005 (Flexera's
# CheckServerCertificate/CheckCertificateRevocation preferences) are
# deliberately not implemented: SECURITY-AUDIT.md cites a Flexera registry
# key for them but does not specify its exact path, and guessing one risks
# reading the wrong value and reporting fabricated evidence. HSTS and
# module-surface minimization are also not yet wired up. All of this is
# left as explicit future work rather than reported with fabricated data.

function Get-HttpsUsageControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$HttpsBindingPresent,
        [Parameter(Mandatory)][bool]$HttpBindingPresent
    )

    $status = if ($HttpsBindingPresent) { 'PASS' } elseif ($HttpBindingPresent) { 'WARNING' } else { 'UNKNOWN' }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-001'
        Category                = 'Transport'
        ObservedValue           = "HTTPS present: $HttpsBindingPresent; HTTP present: $HttpBindingPresent"
        MicrosoftGuidance       = 'Prefer encrypted transport for authentication/data in transit.'
        FlexeraGuidance         = 'HTTPS is the preferred first security improvement for Inventory Beacons.'
        EffectiveRecommendation = 'Prefer HTTPS for Beacon-agent communications.'
        Status                  = $status
        Priority                = 'High'
    }
}

function Get-StandardPortControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][ValidateSet('http', 'https')][string]$Protocol
    )

    $expected = if ($Protocol -eq 'http') { 80 } else { 443 }
    $status = if ($Port -eq $expected) { 'PASS' } else { 'WARNING' }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-002'
        Category                = 'Transport'
        ObservedValue           = "$Protocol on port $Port"
        MicrosoftGuidance       = $null
        FlexeraGuidance         = "Documented IIS web server mode expects $Protocol on port $expected."
        EffectiveRecommendation = 'Do not treat a custom IIS port as automatically equivalent to the documented Flexera IIS port without validating against the deployed Flexera release.'
        Status                  = $status
        Priority                = 'Medium'
    }
}

function Get-BasicAuthenticationControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$BasicAuthEnabled,
        [Parameter(Mandatory)][bool]$HttpsEnforced
    )

    $status = if (-not $BasicAuthEnabled) {
        'NOT_APPLICABLE'
    } elseif ($HttpsEnforced) {
        'PASS'
    } else {
        'FAIL'
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-006'
        Category                = 'Authentication'
        ObservedValue           = "BasicAuth: $BasicAuthEnabled; HTTPS enforced: $HttpsEnforced"
        MicrosoftGuidance       = 'Basic Authentication transmits credentials in clear text unless protected by TLS.'
        FlexeraGuidance         = 'Basic Authentication is supported but Flexera prefers anonymous access and recommends HTTPS as the first security improvement.'
        EffectiveRecommendation = 'Never accept Basic Authentication over unencrypted HTTP.'
        Status                  = $status
        Priority                = 'Critical'
    }
}

function Get-AnonymousAuthenticationControl {
    <#
        Flexera explicitly prefers anonymous authentication for
        Inventory Agent/failover behavior. This is a documented
        product-specific exception to generic upload-authentication
        guidance, so it must resolve to FLEXERA_EXCEPTION rather than a
        generic FAIL (SECURITY-AUDIT.md section 7, control FB-IIS-SEC-007).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$AnonymousEnabled,
        [Parameter(Mandatory)][bool]$HttpsEnforced
    )

    $status = if ($AnonymousEnabled -and $HttpsEnforced) {
        'FLEXERA_EXCEPTION'
    } elseif ($AnonymousEnabled -and -not $HttpsEnforced) {
        'WARNING'
    } else {
        'INFO'
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-007'
        Category                = 'Authentication'
        ObservedValue           = "Anonymous: $AnonymousEnabled; HTTPS enforced: $HttpsEnforced"
        MicrosoftGuidance       = 'Generic guidance recommends authenticating clients before allowing uploads.'
        FlexeraGuidance         = 'Flexera explicitly recommends anonymous authentication where possible for Inventory Agent/failover behavior.'
        EffectiveRecommendation = 'Do not flag anonymous authentication as a generic failure; this is a documented Flexera product exception. Require HTTPS alongside anonymous access.'
        Status                  = $status
        Priority                = 'Medium'
    }
}

function Get-ClientCertificateMode {
    <#
        Decodes IIS's sslFlags bitmask into a client-certificate mode.
        Bit 2 (SslNegotiateCert) = Accept, bit 4 (SslRequireCert) =
        Require (only meaningful together with bit 2); absent = Ignore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$SslFlags
    )

    if ($SslFlags -band 4) { return 'Require' }
    if ($SslFlags -band 2) { return 'Accept' }
    return 'Ignore'
}

function Get-CertificateValidityControl {
    <#
        FB-IIS-SEC-003 (validity sub-check). $Now is an explicit parameter
        rather than an internal Get-Date call so the control stays
        deterministic and testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$NotBefore,
        [Parameter(Mandatory)][datetime]$NotAfter,
        [datetime]$Now = (Get-Date),
        [int]$WarningWindowDays = 30
    )

    $status = if ($Now -lt $NotBefore) {
        'FAIL'
    } elseif ($Now -gt $NotAfter) {
        'FAIL'
    } elseif ($NotAfter -lt $Now.AddDays($WarningWindowDays)) {
        'WARNING'
    } else {
        'PASS'
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-003'
        Category                = 'Transport'
        ObservedValue           = "NotBefore: $($NotBefore.ToString('o')); NotAfter: $($NotAfter.ToString('o'))"
        MicrosoftGuidance       = $null
        FlexeraGuidance         = 'Flexera expects the client to validate the Beacon server certificate; the certificate must be valid and trusted.'
        EffectiveRecommendation = 'Keep the HTTPS server certificate valid and renew it before expiry.'
        Status                  = $status
        Priority                = if ($status -eq 'FAIL') { 'Critical' } else { 'Medium' }
    }
}

function Get-CertificateNameMatchControl {
    <#
        FB-IIS-SEC-003 (name-match sub-check). Wildcard SAN/CN entries
        (e.g. "*.example.com") are matched one label deep; this is a
        best-effort check, not a full RFC 6125 implementation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExpectedHostName,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$CertificateNames
    )

    $status = 'UNKNOWN'

    if ($CertificateNames -and $CertificateNames.Count -gt 0) {
        $match = $CertificateNames | Where-Object {
            if ($_ -eq $ExpectedHostName) { return $true }
            if ($_.StartsWith('*')) {
                $pattern = '^' + [regex]::Escape($_).Replace('\*', '[^.]+') + '$'
                return $ExpectedHostName -match $pattern
            }
            return $false
        }
        $status = if ($match) { 'PASS' } else { 'FAIL' }
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-003'
        Category                = 'Transport'
        ObservedValue           = "Expected host: $ExpectedHostName; certificate names: $($CertificateNames -join ', ')"
        MicrosoftGuidance       = $null
        FlexeraGuidance         = "The certificate's DNS identity must match the server being contacted; local trust does not prove every Inventory Agent trusts the issuing CA."
        EffectiveRecommendation = 'Ensure the certificate Subject/SAN covers the host name Inventory Agents use to reach this Beacon.'
        Status                  = $status
        Priority                = 'High'
    }
}

function Get-MutualTlsControl {
    <#
        FB-IIS-SEC-008: mTLS is an optional enhanced-security profile, not
        a mandatory baseline, so "not configured" is NOT_APPLICABLE rather
        than a failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$HttpsPresent,
        [Parameter(Mandatory)][ValidateSet('Ignore', 'Accept', 'Require')][string]$ClientCertificateMode
    )

    $status = if ($ClientCertificateMode -eq 'Ignore') {
        'NOT_APPLICABLE'
    } elseif ($ClientCertificateMode -eq 'Require' -and -not $HttpsPresent) {
        'FAIL'
    } else {
        'INFO'
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-008'
        Category                = 'Authentication'
        ObservedValue           = "ClientCertificateMode: $ClientCertificateMode; HTTPS present: $HttpsPresent"
        MicrosoftGuidance       = $null
        FlexeraGuidance         = 'Flexera supports mutual TLS as an optional enhanced-security profile; the Beacon validates client-certificate format/validity but does not check client-certificate revocation.'
        EffectiveRecommendation = 'mTLS is optional, not a mandatory baseline. If required, ensure every participating Inventory Agent can present a client certificate.'
        Status                  = $status
        Priority                = 'Informational'
    }
}

function Get-WebDavControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebDavState
    )

    $status = switch ($WebDavState) {
        'Enabled'       { 'FAIL' }
        'Disabled'      { 'PASS' }
        'Not installed' { 'PASS' }
        default         { 'UNKNOWN' }
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-009'
        Category                = 'Attack Surface'
        ObservedValue           = $WebDavState
        MicrosoftGuidance       = 'WebDAV may be useful for publishing scenarios but is unrelated to this workload.'
        FlexeraGuidance         = 'WebDAV must be disabled for IIS-based Inventory Beacons; it can intercept HTTP processing and block inventory functionality.'
        EffectiveRecommendation = 'Keep WebDAV disabled/absent on Flexera IIS paths.'
        Status                  = $status
        Priority                = 'High'
    }
}

function Get-RequestFilteringExtensionControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$ExtensionStates,
        [Parameter(Mandatory)][bool]$RequestFilteringEnabled
    )

    $blocked = @($ExtensionStates.GetEnumerator() | Where-Object { $_.Value -eq 'Blocked' } | ForEach-Object { $_.Key })

    $status = if ($blocked.Count -gt 0) {
        'FAIL'
    } elseif (-not $RequestFilteringEnabled) {
        'WARNING'
    } else {
        'PASS'
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-010'
        Category                = 'Attack Surface'
        ObservedValue           = (($ExtensionStates.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        MicrosoftGuidance       = 'Request Filtering rejects unwanted or potentially harmful requests.'
        FlexeraGuidance         = 'Filtering must not block extensions used by the Inventory Agent, including .osd, .npl, .nds and .ini.'
        EffectiveRecommendation = 'Enable Request Filtering without blocking known Flexera payload extensions.'
        Status                  = $status
        Priority                = if ($blocked.Count -gt 0) { 'Critical' } else { 'Low' }
    }
}

function Get-DirectoryBrowsingControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$Enabled
    )

    $status = if ($Enabled) { 'WARNING' } else { 'PASS' }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-012'
        Category                = 'Attack Surface'
        ObservedValue           = "Directory browsing enabled: $Enabled"
        MicrosoftGuidance       = 'Directory browsing is disabled by default and should stay disabled unless required.'
        FlexeraGuidance         = 'The Directory Browsing role service may be installed as part of the supported feature set without implying the site-level feature must be enabled.'
        EffectiveRecommendation = 'Keep directory browsing disabled at the effective site/path level.'
        Status                  = $status
        Priority                = 'Low'
    }
}

function Get-AppPoolIdentityControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IdentityType
    )

    $status = switch ($IdentityType) {
        'ApplicationPoolIdentity' { 'PASS' }
        'LocalService'            { 'PASS' }
        'NetworkService'          { 'WARNING' }
        'LocalSystem'             { 'FAIL' }
        'SpecificUser'            { 'WARNING' }
        default                   { 'UNKNOWN' }
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-013'
        Category                = 'Isolation'
        ObservedValue           = $IdentityType
        MicrosoftGuidance       = 'Use a unique, low-privilege Application Pool identity such as ApplicationPoolIdentity.'
        FlexeraGuidance         = $null
        EffectiveRecommendation = 'Prefer ApplicationPoolIdentity or another low-privilege isolated identity unless a documented Flexera design requires otherwise.'
        Status                  = $status
        Priority                = if ($IdentityType -eq 'LocalSystem') { 'Critical' } else { 'Medium' }
    }
}

function Get-HttpLoggingControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][bool]$LoggingEnabled,
        [Parameter(Mandatory)][bool]$TimeTakenFieldPresent
    )

    $status = if (-not $LoggingEnabled) {
        'FAIL'
    } elseif (-not $TimeTakenFieldPresent) {
        'WARNING'
    } else {
        'PASS'
    }

    [pscustomobject]@{
        ControlId               = 'FB-IIS-SEC-015'
        Category                = 'Auditability'
        ObservedValue           = "Enabled: $LoggingEnabled; time-taken present: $TimeTakenFieldPresent"
        MicrosoftGuidance       = $null
        FlexeraGuidance         = 'HTTP Logging is part of the documented IIS prerequisites for Inventory Beacons.'
        EffectiveRecommendation = 'Enable W3C logging with fields sufficient for request-level analysis.'
        Status                  = $status
        Priority                = 'Medium'
    }
}

function New-SecurityAuditSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Controls
    )

    $byStatus = $Controls | Group-Object -Property Status | ForEach-Object {
        [pscustomobject]@{ Status = $_.Name; Count = $_.Count }
    }

    [pscustomobject]@{
        TotalControls = $Controls.Count
        ByStatus      = @($byStatus)
    }
}

function Export-SecurityAuditCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Controls,
        [Parameter(Mandatory)][string]$Path
    )

    $Controls |
        Select-Object ControlId, Category, ObservedValue, MicrosoftGuidance, FlexeraGuidance, EffectiveRecommendation, Status, Priority |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Invoke-FlexeraSecurityAudit {
    <#
        Wires the discovered topology/baseline into the control functions
        above. This is a v0.1 orchestration covering only the controls
        that are already backed by discovered data; see the file header
        for what is intentionally not yet implemented.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Topology,
        [Parameter(Mandatory)][object]$Baseline
    )

    $controls = New-Object System.Collections.Generic.List[object]
    $siteHasHttps = @{}

    foreach ($site in @($Topology.SelectedSites)) {
        $httpsBindings = @($site.Bindings | Where-Object { $_.Protocol -eq 'https' })
        $httpBindings  = @($site.Bindings | Where-Object { $_.Protocol -eq 'http' })
        $siteHasHttps[$site.Name] = ($httpsBindings.Count -gt 0)

        $controls.Add((Get-HttpsUsageControl -HttpsBindingPresent ($httpsBindings.Count -gt 0) -HttpBindingPresent ($httpBindings.Count -gt 0))) | Out-Null

        foreach ($b in @($site.Bindings)) {
            if ($b.BindingInformation -match '^(?<ip>[^:]*):(?<port>\d+):(?<host>.*)$') {
                $port = [int]$Matches['port']
                $bindingHost = $Matches['host']

                $controls.Add((Get-StandardPortControl -Port $port -Protocol $b.Protocol)) | Out-Null

                if ($b.Protocol -eq 'https' -and $b.CertificateHash) {
                    $certInfo = $null
                    try { $certInfo = Get-SslCertificateInfo -CertificateHash $b.CertificateHash }
                    catch { $certInfo = $null }

                    if ($certInfo) {
                        $controls.Add((Get-CertificateValidityControl -NotBefore $certInfo.NotBefore -NotAfter $certInfo.NotAfter)) | Out-Null

                        if ($bindingHost) {
                            $certNames = @($certInfo.SubjectAltNames)
                            if ($certInfo.Subject -match 'CN=([^,]+)') { $certNames += $Matches[1].Trim() }
                            $controls.Add((Get-CertificateNameMatchControl -ExpectedHostName $bindingHost -CertificateNames @($certNames | Select-Object -Unique))) | Out-Null
                        }
                    }

                    $clientCertMode = Get-ClientCertificateMode -SslFlags ([int]$b.SslFlags)
                    $controls.Add((Get-MutualTlsControl -HttpsPresent $true -ClientCertificateMode $clientCertMode)) | Out-Null
                }
            }
        }
    }

    foreach ($pool in @($Topology.SelectedAppPools)) {
        $controls.Add((Get-AppPoolIdentityControl -IdentityType $pool.IdentityType)) | Out-Null
    }

    foreach ($endpoint in @($Baseline.Endpoints)) {
        $controls.Add((Get-WebDavControl -WebDavState $endpoint.WebDav)) | Out-Null

        if ($endpoint.RequestFiltering -and $endpoint.RequestFiltering.Count -gt 0) {
            $controls.Add((Get-RequestFilteringExtensionControl -ExtensionStates $endpoint.RequestFiltering -RequestFilteringEnabled $true)) | Out-Null
        }

        $httpsEnforced = [bool]$siteHasHttps[$endpoint.Site]

        if ($endpoint.Authentication) {
            if ($null -ne $endpoint.Authentication.BasicEnabled) {
                $controls.Add((Get-BasicAuthenticationControl -BasicAuthEnabled ([bool]$endpoint.Authentication.BasicEnabled) -HttpsEnforced $httpsEnforced)) | Out-Null
            }
            if ($null -ne $endpoint.Authentication.AnonymousEnabled) {
                $controls.Add((Get-AnonymousAuthenticationControl -AnonymousEnabled ([bool]$endpoint.Authentication.AnonymousEnabled) -HttpsEnforced $httpsEnforced)) | Out-Null
            }
        }
    }

    foreach ($siteLogging in @($Baseline.Logging)) {
        if ($siteLogging.Enabled -is [bool]) {
            $timeTakenPresent = @($siteLogging.EnabledFields) -contains 'time-taken'
            $controls.Add((Get-HttpLoggingControl -LoggingEnabled $siteLogging.Enabled -TimeTakenFieldPresent $timeTakenPresent)) | Out-Null
        } else {
            $controls.Add([pscustomobject]@{
                ControlId               = 'FB-IIS-SEC-015'
                Category                = 'Auditability'
                ObservedValue           = "Enabled: $($siteLogging.Enabled)"
                MicrosoftGuidance       = $null
                FlexeraGuidance         = 'HTTP Logging is part of the documented IIS prerequisites for Inventory Beacons.'
                EffectiveRecommendation = 'Could not read the effective logging configuration for this site; verify HTTP Logging manually.'
                Status                  = 'UNKNOWN'
                Priority                = 'Medium'
            }) | Out-Null
        }
    }

    foreach ($finding in @($Baseline.AuthenticationConsistency)) {
        $controls.Add($finding) | Out-Null
    }

    return $controls.ToArray()
}
