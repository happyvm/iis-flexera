# Read-only Microsoft-vs-Flexera IIS security audit.
#
# Every control below is a pure decision function: given observed values,
# it returns a status from the model in SECURITY-AUDIT.md section 4. This
# keeps the compatibility logic (e.g. why anonymous authentication is a
# FLEXERA_EXCEPTION rather than a generic failure) independently testable
# without needing a live IIS host.
#
# v0.1 scope note: this file implements a first subset of the full control
# catalogue in SECURITY-AUDIT.md section 7 (HTTPS, port, Basic/Anonymous
# authentication, WebDAV, Request Filtering, directory browsing, AppPool
# identity, HTTP logging). TLS certificate metadata, mutual TLS, HSTS,
# module-surface minimization and configuration-inheritance provenance are
# not yet wired up and are left as explicit future work rather than
# reported with fabricated data.

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

    foreach ($site in @($Topology.SelectedSites)) {
        $httpsBindings = @($site.Bindings | Where-Object { $_.Protocol -eq 'https' })
        $httpBindings  = @($site.Bindings | Where-Object { $_.Protocol -eq 'http' })

        $controls.Add((Get-HttpsUsageControl -HttpsBindingPresent ($httpsBindings.Count -gt 0) -HttpBindingPresent ($httpBindings.Count -gt 0))) | Out-Null

        foreach ($b in @($site.Bindings)) {
            if ($b.BindingInformation -match ':(?<port>\d+):') {
                $controls.Add((Get-StandardPortControl -Port ([int]$Matches['port']) -Protocol $b.Protocol)) | Out-Null
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
    }

    return @($controls)
}
