# Read-only Flexera IIS configuration-baseline snapshot.
#
# Captures the configuration evidence described in FLEXERA-IIS-BASELINE.md
# without ever changing the server. A missing prerequisite or an
# undetectable setting is recorded as evidence, not treated as permission
# to remediate (FLEXERA-IIS-BASELINE.md section 1).

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

    Import-Module WebAdministration -ErrorAction Stop

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

    Import-Module WebAdministration -ErrorAction Stop

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
        $sitePath = "IIS:\Sites\$($endpoint.SiteName)$($endpoint.Path)"

        $webDav = 'Unknown'
        $requestFiltering = [ordered]@{}

        try { $webDav = Get-WebDavState -SitePath $sitePath }
        catch { $warnings.Add("WebDAV check failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        try { $requestFiltering = Get-RequestFilteringExtensionState -SitePath $sitePath -Extensions $endpointExtensions }
        catch { $warnings.Add("Request Filtering check failed for '$($endpoint.EndpointName)': $($_.Exception.Message)") | Out-Null }

        [pscustomobject]@{
            Name             = $endpoint.EndpointName
            Site             = $endpoint.SiteName
            AppPool          = $endpoint.AppPoolName
            Path             = $endpoint.Path
            WebDav           = $webDav
            RequestFiltering = $requestFiltering
        }
    }

    [pscustomobject]@{
        FlexeraBaselineVersion = 1
        CapturedAt             = (Get-Date).ToString('o')
        Iis                    = [pscustomobject]@{
            Version      = $Topology.IisVersion
            RoleServices = $roleServiceStatus
        }
        Sites     = $Topology.SelectedSites
        AppPools  = $Topology.SelectedAppPools
        Endpoints = @($endpointBaselines)
        Warnings  = @($warnings)
    }
}
