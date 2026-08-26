# IIS/Flexera topology discovery.
#
# ManageSoftRL/ManageSoftDL are discovery hints, not proof of a fixed
# topology: an AppPool named "Flexera Beacon" is not sufficient by itself
# to identify the pool serving downstream agent traffic
# (FLEXERA-IIS-BASELINE.md section 10, SPECIFICATION.md section 5).

function Test-WebAdministrationAvailable {
    [CmdletBinding()]
    param()

    return [bool](Get-Module -ListAvailable -Name WebAdministration)
}

function Get-IisVersion {
    [CmdletBinding()]
    param()

    try {
        $key = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction Stop
        return "$($key.MajorVersion).$($key.MinorVersion)"
    } catch {
        return $null
    }
}

function Get-IisFlexeraEndpoints {
    <#
        Enumerates IIS applications and virtual directories and matches
        them against known Flexera endpoint names (default:
        ManageSoftRL/ManageSoftDL), then resolves each match's site and
        Application Pool. SPECIFICATION.md section 5.3.
    #>
    [CmdletBinding()]
    param(
        [string[]]$KnownEndpointNames = @('ManageSoftRL', 'ManageSoftDL'),
        [string]$SiteName,
        [string]$AppPoolName
    )

    if (-not (Test-WebAdministrationAvailable)) {
        throw 'The WebAdministration module is not available. Run this on a Windows Server with IIS management tools installed.'
    }

    Import-Module WebAdministration -ErrorAction Stop

    $sites = Get-ChildItem -Path 'IIS:\Sites'
    $matchedEndpoints = New-Object System.Collections.Generic.List[object]

    foreach ($site in $sites) {
        if ($SiteName -and $site.Name -ne $SiteName) { continue }

        $apps  = @(Get-WebApplication -Site $site.Name -ErrorAction SilentlyContinue)
        $vdirs = @(Get-WebVirtualDirectory -Site $site.Name -ErrorAction SilentlyContinue)

        $candidates = New-Object System.Collections.Generic.List[object]
        foreach ($a in $apps) {
            $candidates.Add([pscustomobject]@{ Path = $a.Path; PhysicalPath = $a.PhysicalPath; AppPoolName = $a.applicationPool }) | Out-Null
        }
        foreach ($v in $vdirs) {
            $candidates.Add([pscustomobject]@{ Path = $v.Path; PhysicalPath = $v.PhysicalPath; AppPoolName = $null }) | Out-Null
        }

        foreach ($endpointName in $KnownEndpointNames) {
            $hits = @($candidates | Where-Object { $_.Path -match "(^|/)$([regex]::Escape($endpointName))$" })

            foreach ($h in $hits) {
                $resolvedPool = $h.AppPoolName
                if (-not $resolvedPool) {
                    # Virtual directories inherit the parent application's pool.
                    $parentApp = $apps |
                        Where-Object { $h.Path -eq $_.Path -or $h.Path.StartsWith("$($_.Path)/") } |
                        Sort-Object { $_.Path.Length } -Descending |
                        Select-Object -First 1
                    if ($parentApp) { $resolvedPool = $parentApp.applicationPool }
                }

                $matchedEndpoints.Add([pscustomobject]@{
                    EndpointName = $endpointName
                    SiteName     = $site.Name
                    SiteId       = $site.id
                    Path         = $h.Path
                    PhysicalPath = $h.PhysicalPath
                    AppPoolName  = $resolvedPool
                }) | Out-Null
            }
        }
    }

    if ($matchedEndpoints.Count -eq 0 -and $AppPoolName) {
        $matchedEndpoints.Add([pscustomobject]@{
            EndpointName = $null
            SiteName     = $SiteName
            SiteId       = $null
            Path         = $null
            PhysicalPath = $null
            AppPoolName  = $AppPoolName
        }) | Out-Null
    }

    return $matchedEndpoints
}

function Get-IisSiteInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    Import-Module WebAdministration -ErrorAction Stop
    $site = Get-Item "IIS:\Sites\$Name" -ErrorAction Stop

    $bindings = @($site.bindings.Collection | ForEach-Object {
        [pscustomobject]@{
            Protocol            = $_.protocol
            BindingInformation  = $_.bindingInformation
            CertificateHash     = $_.certificateHash
            SslFlags            = $_.sslFlags
        }
    })

    [pscustomobject]@{
        Name         = $site.Name
        Id           = $site.id
        State        = $site.state
        PhysicalPath = $site.physicalPath
        Bindings     = $bindings
    }
}

function Get-IisAppPoolInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    Import-Module WebAdministration -ErrorAction Stop
    $pool = Get-Item "IIS:\AppPools\$Name" -ErrorAction Stop

    [pscustomobject]@{
        Name            = $Name
        State           = $pool.state
        QueueLength     = $pool.queueLength
        MaxProcesses    = $pool.processModel.maxProcesses
        IdentityType    = $pool.processModel.identityType
        UserName        = $pool.processModel.userName
        PipelineMode    = $pool.managedPipelineMode
        RuntimeVersion  = $pool.managedRuntimeVersion
        StartMode       = $pool.startMode
        LoadUserProfile = $pool.processModel.loadUserProfile
    }
}

function Invoke-FlexeraIisDiscovery {
    <#
        Ties endpoint/site/AppPool discovery together and applies the
        selection rule from SPECIFICATION.md section 5.3: if no Flexera
        endpoint and no explicit override resolve to an Application Pool,
        terminate before starting an unattended run rather than silently
        monitoring the wrong pool.
    #>
    [CmdletBinding()]
    param(
        [string]$SiteName,
        [string]$AppPoolName,
        [string[]]$KnownEndpointNames = @('ManageSoftRL', 'ManageSoftDL')
    )

    $warnings = New-Object System.Collections.Generic.List[string]

    $endpoints = @()
    try {
        $endpoints = Get-IisFlexeraEndpoints -KnownEndpointNames $KnownEndpointNames -SiteName $SiteName -AppPoolName $AppPoolName
    } catch {
        $warnings.Add("Flexera endpoint discovery failed: $($_.Exception.Message)")
    }

    $resolvedPools = @($endpoints | Where-Object { $_.AppPoolName } | Select-Object -ExpandProperty AppPoolName -Unique)

    if (-not $resolvedPools -and $AppPoolName) {
        $resolvedPools = @($AppPoolName)
        $warnings.Add("No known Flexera endpoint (ManageSoftRL/ManageSoftDL) was discovered; using explicitly supplied -AppPoolName '$AppPoolName'.")
    }

    if (-not $resolvedPools) {
        throw 'Unable to determine which Application Pool serves Flexera traffic. No ManageSoftRL/ManageSoftDL endpoint was found and no -SiteName/-AppPoolName override was supplied. Refusing to start an unattended run against an ambiguous target.'
    }

    $sites = @($endpoints | Where-Object { $_.SiteName } | Select-Object -ExpandProperty SiteName -Unique)
    if (-not $sites -and $SiteName) { $sites = @($SiteName) }

    $siteInfo = New-Object System.Collections.Generic.List[object]
    foreach ($s in $sites) {
        try { $siteInfo.Add((Get-IisSiteInfo -Name $s)) | Out-Null }
        catch { $warnings.Add("Could not read site info for '$s': $($_.Exception.Message)") }
    }

    $poolInfo = New-Object System.Collections.Generic.List[object]
    foreach ($p in $resolvedPools) {
        try { $poolInfo.Add((Get-IisAppPoolInfo -Name $p)) | Out-Null }
        catch { $warnings.Add("Could not read AppPool info for '$p': $($_.Exception.Message)") }
    }

    [pscustomobject]@{
        IisVersion       = Get-IisVersion
        Endpoints        = $endpoints
        SelectedSites    = @($siteInfo)
        SelectedAppPools = @($poolInfo)
        Warnings         = @($warnings)
    }
}
