# Read-only Flexera IIS configuration-baseline snapshot.
#
# Captures the configuration evidence described in FLEXERA-IIS-BASELINE.md
# without ever changing the server. A missing prerequisite or an
# undetectable setting is recorded as evidence, not treated as permission
# to remediate (FLEXERA-IIS-BASELINE.md section 1).
#
# Depends on Import-WebAdministrationModule from src/Discovery.ps1 being
# defined; dot-source Discovery.ps1 before this file.

function Get-IisRoleServiceStatus {
    <#
        Returns Present/Missing/Not detectable for each named Windows
        feature. Get-WindowsFeature requires the ServerManager module,
        which is not present on every SKU/edition - that case is reported
        as "Not detectable" rather than assumed absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$FeatureNames
    )

    $results = [ordered]@{}
    $hasServerManager = [bool](Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue)

    foreach ($name in $FeatureNames) {
        if (-not $hasServerManager) {
            $results[$name] = 'Not detectable'
            continue
        }

        try {
            $feature = Get-WindowsFeature -Name $name -ErrorAction Stop
            $results[$name] = if ($feature.Installed) { 'Present' } else { 'Missing' }
        } catch {
            $results[$name] = 'Not detectable'
        }
    }

    return $results
}

function Get-WebDavState {
    <#
        Reports the effective WebDAV state for a site/path: Disabled,
        Enabled, Not installed or Unknown. This must be validated against
        a real WebDAV-enabled IIS host; on any read failure it reports
        Unknown rather than guessing (FLEXERA-IIS-BASELINE.md section 5).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SitePath
    )

    Import-WebAdministrationModule

    $moduleInstalled = [bool](Get-WebGlobalModule -Name 'WebDAVModule' -ErrorAction SilentlyContinue)
    if (-not $moduleInstalled) { return 'Not installed' }

    try {
        $enabled = (Get-WebConfigurationProperty -Filter '/system.webServer/webdav/authoring' -PSPath $SitePath -Name enabled -ErrorAction Stop).Value
        return $(if ($enabled) { 'Enabled' } else { 'Disabled' })
    } catch {
        return 'Unknown'
    }
}

function Get-RequestFilteringExtensionState {
    <#
        Reports Allowed/Blocked/NotExplicitlyConfigured for each extension,
        so the caller can check that Flexera payload types (.osd, .npl,
        .nds, .ini) are not being denied (FLEXERA-IIS-BASELINE.md section 6).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SitePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Extensions
    )

    Import-WebAdministrationModule

    $result = [ordered]@{}
    foreach ($ext in $Extensions) {
        try {
            $rule = Get-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/fileExtensions/add[@fileExtension='$ext']" -PSPath $SitePath -Name allowed -ErrorAction Stop
            $result[$ext] = if ($rule.Value -eq $false) { 'Blocked' } else { 'Allowed' }
        } catch {
            $result[$ext] = 'NotExplicitlyConfigured'
        }
    }

    return $result
}

function Get-IisRequestFilteringConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SitePath)

    Import-WebAdministrationModule
    $section = Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath $SitePath -ErrorAction Stop
    [pscustomobject]@{
        AllowUnlistedVerbs = $section.verbs.allowUnlisted
        Verbs = @($section.verbs.Collection | ForEach-Object { [pscustomobject]@{ Verb = "$($_.verb)"; Allowed = $_.allowed } })
        AllowUnlistedFileExtensions = $section.fileExtensions.allowUnlisted
        FileExtensions = @($section.fileExtensions.Collection | ForEach-Object { [pscustomobject]@{ Extension = "$($_.fileExtension)"; Allowed = $_.allowed } })
        HiddenSegments = @($section.hiddenSegments.Collection | ForEach-Object { "$($_.segment)" })
        MaxAllowedContentLength = $section.requestLimits.maxAllowedContentLength
        MaxUrl = $section.requestLimits.maxUrl
        MaxQueryString = $section.requestLimits.maxQueryString
    }
}

function Get-IisHandlerAndModuleConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SitePath)

    Import-WebAdministrationModule
    $handlers = Get-WebConfiguration -Filter 'system.webServer/handlers' -PSPath $SitePath -ErrorAction Stop
    $modules = Get-WebConfiguration -Filter 'system.webServer/modules' -PSPath $SitePath -ErrorAction Stop
    [pscustomobject]@{
        Handlers = @($handlers.Collection | ForEach-Object {
            [pscustomobject]@{
                Name = "$($_.name)"; Path = "$($_.path)"; Verb = "$($_.verb)"; Modules = "$($_.modules)"
                ScriptProcessor = "$($_.scriptProcessor)"; ResourceType = "$($_.resourceType)"
                RequireAccess = "$($_.requireAccess)"; PreCondition = "$($_.preCondition)"
            }
        })
        Modules = @($modules.Collection | ForEach-Object { [pscustomobject]@{ Name = "$($_.name)"; PreCondition = "$($_.preCondition)" } })
    }
}

function Get-IisAuthenticationState {
    <#
        Reads the effective Anonymous/Basic/Windows authentication state
        for a site/path. Never reads credentials - only the enabled/
        disabled flag per provider (FLEXERA-IIS-BASELINE.md section 3).
        A provider whose state cannot be read is left $null rather than
        assumed disabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SitePath
    )

    Import-WebAdministrationModule

    function Get-AuthFlag([string]$Path, [string]$Section) {
        try {
            $prop = Get-WebConfigurationProperty -Filter "/system.webServer/security/authentication/$Section" -PSPath $Path -Name enabled -ErrorAction Stop
            return [bool]$prop.Value
        } catch {
            return $null
        }
    }

    [pscustomobject]@{
        AnonymousEnabled = Get-AuthFlag -Path $SitePath -Section 'anonymousAuthentication'
        BasicEnabled     = Get-AuthFlag -Path $SitePath -Section 'basicAuthentication'
        WindowsEnabled   = Get-AuthFlag -Path $SitePath -Section 'windowsAuthentication'
    }
}

function Get-BeaconTopologyType {
    <#
        Flexera documents that a standalone Beacon's ManageSoftRL and
        ManageSoftDL share the same directory and web.config
        (FLEXERA-IIS-BASELINE.md section 3.1). Identical physical paths
        are used as the observable proxy for that; a difference is
        reported as 'Distinct' rather than asserted to be the co-installed
        topology, since that cannot be confirmed from physical path alone.
    #>
    [CmdletBinding()]
    param(
        [string]$RLPhysicalPath,
        [string]$DLPhysicalPath
    )

    if ([string]::IsNullOrWhiteSpace($RLPhysicalPath) -or [string]::IsNullOrWhiteSpace($DLPhysicalPath)) {
        return 'Unknown'
    }

    if ($RLPhysicalPath -eq $DLPhysicalPath) { return 'Standalone' }
    return 'Distinct'
}

function Get-AuthenticationConsistencyFinding {
    <#
        FB-IIS-BASE-001: for a confidently standalone topology, Flexera
        documents that mismatched authentication between ManageSoftRL and
        ManageSoftDL causes HTTP 409 upload failures
        (FLEXERA-IIS-BASELINE.md section 3.1). When topology cannot be
        confirmed as standalone, the finding is NOT_APPLICABLE rather than
        a failure, per the "do not declare non-compliant when topology is
        unclear" rule in section 15.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Standalone', 'Distinct', 'Unknown')][string]$TopologyType,
        [object]$RLAuth,
        [object]$DLAuth,
        [string]$Scope
    )

    $base = [ordered]@{
        ControlId               = 'FB-IIS-BASE-001'
        Category                = 'Authentication'
        Scope                   = $Scope
        ObservedValue           = "Topology: $TopologyType"
        MicrosoftGuidance       = $null
        FlexeraGuidance         = 'A standalone Beacon shares one directory/web.config for ManageSoftRL and ManageSoftDL, so both must use consistent authentication; Flexera documents HTTP 409 upload failures otherwise. A co-installed Beacon may intentionally use different authentication per location.'
        EffectiveRecommendation = $null
        Status                  = $null
        Priority                = 'Medium'
    }

    if ($TopologyType -ne 'Standalone') {
        $base.EffectiveRecommendation = 'Topology is not confidently standalone (ManageSoftRL/ManageSoftDL physical paths differ or are unknown); do not require matching authentication between the two locations.'
        $base.Status = 'NOT_APPLICABLE'
        $base.Priority = 'Informational'
        return [pscustomobject]$base
    }

    if (-not $RLAuth -or -not $DLAuth) {
        $base.EffectiveRecommendation = 'Standalone topology detected but effective authentication could not be read for one or both locations.'
        $base.Status = 'UNKNOWN'
        return [pscustomobject]$base
    }

    $match = ($RLAuth.AnonymousEnabled -eq $DLAuth.AnonymousEnabled) -and
             ($RLAuth.BasicEnabled -eq $DLAuth.BasicEnabled) -and
             ($RLAuth.WindowsEnabled -eq $DLAuth.WindowsEnabled)

    $base.ObservedValue = "Topology: $TopologyType; RL: Anonymous=$($RLAuth.AnonymousEnabled), Basic=$($RLAuth.BasicEnabled), Windows=$($RLAuth.WindowsEnabled); DL: Anonymous=$($DLAuth.AnonymousEnabled), Basic=$($DLAuth.BasicEnabled), Windows=$($DLAuth.WindowsEnabled)"

    if ($match) {
        $base.EffectiveRecommendation = 'Authentication is consistent between ManageSoftRL and ManageSoftDL, as required for a standalone Beacon.'
        $base.Status = 'PASS'
    } else {
        $base.EffectiveRecommendation = 'ManageSoftRL and ManageSoftDL use inconsistent authentication despite sharing a directory/web.config; Flexera documents this as a cause of HTTP 409 upload failures. Align the authentication settings for both locations.'
        $base.Status = 'FAIL'
        $base.Priority = 'High'
    }

    return [pscustomobject]$base
}

function Get-IisLoggingConfiguration {
    <#
        Reads the site's logFile configuration and maps IIS's
        logExtFileFlags names to the canonical W3C field names used
        elsewhere in this project (FLEXERA-IIS-BASELINE.md section 7).
        IIS does not expose one universal "logging enabled" boolean once
        the HTTP Logging role service is present; this reports the
        logFile section's presence/format as the closest available
        signal and must be validated against a real IIS host. Field
        mapping only applies when LogFormat is W3C.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteName
    )

    Import-WebAdministrationModule

    $fieldMap = [ordered]@{
        'Date' = 'date'; 'Time' = 'time'; 'SiteName' = 's-sitename'; 'Method' = 'cs-method'
        'UriStem' = 'cs-uri-stem'; 'UriQuery' = 'cs-uri-query'; 'HttpStatus' = 'sc-status'
        'HttpSubStatus' = 'sc-substatus'; 'Win32Status' = 'sc-win32-status'
        'BytesRecv' = 'cs-bytes'; 'BytesSent' = 'sc-bytes'; 'TimeTaken' = 'time-taken'
        'ClientIP' = 'c-ip'; 'ServerIP' = 's-ip'; 'UserAgent' = 'cs(User-Agent)'
        'UserName' = 'cs-username'; 'Host' = 'cs-host'; 'ProtocolVersion' = 'cs-version'
    }

    try {
        $escapedName = $SiteName.Replace("'", "''")
        $logFile = Get-WebConfiguration -Filter "system.applicationHost/sites/site[@name='$escapedName']/logFile" -PSPath 'MACHINE/WEBROOT/APPHOST' -ErrorAction Stop
        if (-not $logFile) { throw "Site '$SiteName' not found." }
    } catch {
        return [pscustomobject]@{
            SiteName = $SiteName; Enabled = 'Unknown'; LogFormat = $null; Directory = $null; EnabledFields = @()
        }
    }

    $logFormat = "$($logFile.logFormat)"
    $mappedFields = @()

    if ($logFormat -eq 'W3C') {
        $rawFlags = @("$($logFile.logExtFileFlags)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $mappedFields = @($rawFlags | ForEach-Object { if ($fieldMap.Contains($_)) { $fieldMap[$_] } } | Where-Object { $_ })
    }

    [pscustomobject]@{
        SiteName      = $SiteName
        Enabled       = $true
        LogFormat     = $logFormat
        Directory     = "$($logFile.directory)"
        EnabledFields = $mappedFields
    }
}

function Test-RequiredW3CFieldsPresent {
    <#
        Checks the fields this project needs against what is actually
        enabled, and explains which analyses become unavailable for each
        missing field, per SPECIFICATION.md section 16. Never silently
        fabricates a missing metric.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$EnabledFields
    )

    $requiredFieldImpacts = [ordered]@{
        'date'            = 'timestamps cannot be computed; all time-based analysis is unavailable'
        'time'            = 'timestamps cannot be computed; all time-based analysis is unavailable'
        's-sitename'      = 'requests cannot be attributed to a specific site'
        'cs-method'       = 'requests cannot be broken down by HTTP method'
        'cs-uri-stem'     = 'endpoint-level aggregation (top endpoints, per-endpoint latency) is unavailable'
        'sc-status'       = 'HTTP status-code distribution is unavailable'
        'sc-substatus'    = 'detailed IIS status-code breakdown (e.g. 401.2) is unavailable'
        'sc-win32-status' = 'Win32 failure-code diagnosis is unavailable'
        'cs-bytes'        = 'inbound request-byte analysis is unavailable'
        'sc-bytes'        = 'outbound response-byte analysis is unavailable'
        'time-taken'      = 'latency percentiles (P50/P95/P99) are unavailable'
        'c-ip'            = 'HTTP 405 responses cannot be attributed to a client; this field is currently not logged and enabling it would improve diagnostics'
        'cs(User-Agent)'  = 'agent/client software cannot be distinguished; this field is currently not logged and enabling it would improve diagnostics'
    }

    $missing = New-Object System.Collections.Generic.List[psobject]
    foreach ($field in $requiredFieldImpacts.Keys) {
        if ($EnabledFields -notcontains $field) {
            $missing.Add([pscustomobject]@{ Field = $field; Impact = $requiredFieldImpacts[$field] }) | Out-Null
        }
    }

    [pscustomobject]@{
        MissingFields            = $missing.ToArray()
        AllRequiredFieldsPresent = ($missing.Count -eq 0)
    }
}

function New-FlexeraConfigurationBaseline {
    <#
        Produces the configuration-baseline.json structure suggested in
        FLEXERA-IIS-BASELINE.md section 14. Any individual check that
        fails is recorded as a warning; it never aborts the whole
        snapshot and never fabricates a value for the failed check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Topology
    )

    $warnings = New-Object System.Collections.Generic.List[string]
    foreach ($w in @($Topology.Warnings)) { $warnings.Add($w) | Out-Null }

    $prereqFeatures = @(
        'Web-Net-Ext45', 'Web-Asp-Net45', 'Web-ISAPI-Ext', 'Web-Http-Errors',
        'Web-Static-Content', 'Web-Http-Logging', 'Web-Dyn-Compression',
        'Web-Stat-Compression', 'Web-Basic-Auth', 'Web-Windows-Auth'
    )

    $roleServiceStatus = [ordered]@{}
    try {
        $roleServiceStatus = Get-IisRoleServiceStatus -FeatureNames $prereqFeatures
    } catch {
        $warnings.Add("Could not enumerate Windows IIS role services: $($_.Exception.Message)") | Out-Null
    }

    $endpointExtensions = @('.osd', '.npl', '.nds', '.ini')

    $endpointBaselines = foreach ($endpoint in @($Topology.Endpoints)) {
        # MACHINE/WEBROOT/APPHOST/... rather than IIS:\Sites\... - see
        # Import-WebAdministrationModule in src/Discovery.ps1 for why.
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($endpoint.SiteName)$($endpoint.Path)"

        $webDav = 'Unknown'
        $requestFiltering = [ordered]@{}
        $authentication = $null
        $requestFilteringDetail = $null
        $handlerAndModules = $null

        try { $webDav = Get-WebDavState -SitePath $sitePath }
        catch { $warnings.Add("WebDAV check failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        try { $requestFiltering = Get-RequestFilteringExtensionState -SitePath $sitePath -Extensions $endpointExtensions }
        catch { $warnings.Add("Request Filtering check failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        try { $authentication = Get-IisAuthenticationState -SitePath $sitePath }
        catch { $warnings.Add("Authentication check failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        try { $requestFilteringDetail = Get-IisRequestFilteringConfiguration -SitePath $sitePath }
        catch { $warnings.Add("Detailed Request Filtering capture failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        try { $handlerAndModules = Get-IisHandlerAndModuleConfiguration -SitePath $sitePath }
        catch { $warnings.Add("Handler/module capture failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        [pscustomobject]@{
            Name             = $endpoint.EndpointName
            Site             = $endpoint.SiteName
            AppPool          = $endpoint.AppPoolName
            Path             = $endpoint.Path
            PhysicalPath     = $endpoint.PhysicalPath
            WebDav           = $webDav
            RequestFiltering = $requestFiltering
            Authentication   = $authentication
            RequestFilteringDetail = $requestFilteringDetail
            Handlers         = if ($handlerAndModules) { $handlerAndModules.Handlers } else { @() }
            Modules          = if ($handlerAndModules) { $handlerAndModules.Modules } else { @() }
        }
    }
    $endpointBaselines = @($endpointBaselines)

    $siteNames = @($Topology.SelectedSites | Select-Object -ExpandProperty Name -Unique)
    $loggingBySite = foreach ($siteName in $siteNames) {
        try {
            $loggingConfig = Get-IisLoggingConfiguration -SiteName $siteName
            $fieldCheck = Test-RequiredW3CFieldsPresent -EnabledFields $loggingConfig.EnabledFields
            [pscustomobject]@{
                SiteName                 = $siteName
                Enabled                  = $loggingConfig.Enabled
                LogFormat                = $loggingConfig.LogFormat
                Directory                = $loggingConfig.Directory
                EnabledFields            = $loggingConfig.EnabledFields
                MissingFields            = $fieldCheck.MissingFields
                AllRequiredFieldsPresent = $fieldCheck.AllRequiredFieldsPresent
            }
        } catch {
            $warnings.Add("Logging configuration check failed for site '$siteName': $($_.Exception.Message)") | Out-Null
        }
    }
    $loggingBySite = @($loggingBySite)

    # Pair ManageSoftRL/ManageSoftDL within the same site to evaluate the
    # standalone authentication-consistency rule (FLEXERA-IIS-BASELINE.md
    # section 3.1); other endpoint names are not evaluated for this rule.
    $authConsistencyFindings = foreach ($siteName in $siteNames) {
        $rl = $endpointBaselines | Where-Object { $_.Site -eq $siteName -and $_.Name -eq 'ManageSoftRL' } | Select-Object -First 1
        $dl = $endpointBaselines | Where-Object { $_.Site -eq $siteName -and $_.Name -eq 'ManageSoftDL' } | Select-Object -First 1

        if ($rl -and $dl) {
            $topologyType = Get-BeaconTopologyType -RLPhysicalPath $rl.PhysicalPath -DLPhysicalPath $dl.PhysicalPath
            Get-AuthenticationConsistencyFinding -TopologyType $topologyType -RLAuth $rl.Authentication -DLAuth $dl.Authentication -Scope $siteName
        }
    }
    $authConsistencyFindings = @($authConsistencyFindings)

    [pscustomobject]@{
        FlexeraBaselineVersion     = 2
        CapturedAt                 = (Get-Date).ToUniversalTime().ToString('o')
        Iis                        = [pscustomobject]@{
            Version      = $Topology.IisVersion
            RoleServices = $roleServiceStatus
        }
        Sites                      = $Topology.SelectedSites
        AppPools                   = $Topology.SelectedAppPools
        Endpoints                  = $endpointBaselines
        Logging                    = $loggingBySite
        AuthenticationConsistency  = $authConsistencyFindings
        Warnings                   = @($warnings)
    }
}
