# IIS/Flexera topology discovery.
#
# ManageSoftRL/ManageSoftDL are discovery hints, not proof of a fixed
# topology: an AppPool named "Flexera Beacon" is not sufficient by itself
# to identify the pool serving downstream agent traffic
# (FLEXERA-IIS-BASELINE.md section 10, SPECIFICATION.md section 5).

function Import-WebAdministrationModule {
    <#
        Centralizes WebAdministration loading so the PowerShell 7
        fallback below only needs to exist once. Under PowerShell 7/Core,
        Get-Module -ListAvailable frequently cannot see WebAdministration
        at all (it is a Windows PowerShell 5.1 module, and PS7's default
        $env:PSModulePath does not include the Windows PowerShell system
        module path) even though it is installed and works fine under
        powershell.exe. When that happens, load it explicitly through the
        Windows PowerShell compatibility layer instead of concluding the
        module is missing.

        This project deliberately avoids the module's IIS:\ PSDrive
        everywhere (Get-Website/Get-WebConfiguration with a
        "MACHINE/WEBROOT/APPHOST/..." configuration path instead of
        Get-Item "IIS:\..."), because loading through the PowerShell 7
        compatibility layer only proxies cmdlets, not the module's custom
        PSProvider - so IIS:\ paths do not work there even once the
        module itself loads successfully, and there is no known
        workaround for that short of not using IIS:\ at all.
    #>
    [CmdletBinding()]
    param()

    if (Get-Module -Name WebAdministration) { return }

    if ($PSVersionTable.PSEdition -eq 'Core') {
        try {
            Import-Module WebAdministration -UseWindowsPowerShell -ErrorAction Stop
            return
        } catch {
            throw "The WebAdministration module could not be loaded via the Windows PowerShell compatibility layer under PowerShell $($PSVersionTable.PSVersion): $($_.Exception.Message). This project targets Windows PowerShell 5.1 first (SPECIFICATION.md section 4); retry under powershell.exe."
        }
    }

    Import-Module WebAdministration -ErrorAction Stop
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

    Import-WebAdministrationModule

    $sites = @(Get-Website)
    $matchedEndpoints = New-Object System.Collections.Generic.List[object]

    foreach ($site in $sites) {
        if ($SiteName -and $site.Name -ne $SiteName) { continue }

        # Errors here are surfaced via Write-Warning rather than swallowed
        # with -ErrorAction SilentlyContinue: under PowerShell 7, the
        # WebAdministration module runs through the Windows PowerShell
        # compatibility layer and these cmdlets can fail without an
        # obvious symptom other than "nothing was found" - which is
        # otherwise indistinguishable from a genuinely empty site.
        $apps = @()
        try {
            $apps = @(Get-WebApplication -Site $site.Name -ErrorAction Stop)
        } catch {
            Write-Warning "Get-WebApplication failed for site '$($site.Name)': $($_.Exception.Message)"
        }

        $vdirs = @()
        try {
            $vdirs = @(Get-WebVirtualDirectory -Site $site.Name -ErrorAction Stop)
        } catch {
            Write-Warning "Get-WebVirtualDirectory failed for site '$($site.Name)': $($_.Exception.Message)"
        }

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

    Import-WebAdministrationModule
    $site = Get-Website -Name $Name | Select-Object -First 1
    if (-not $site) { throw "Site '$Name' not found." }

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

function Get-SslCertificateInfo {
    <#
        Resolves the X.509 certificate bound via an HTTPS binding's
        certificateHash/certificateStoreName, using only local metadata
        APIs. Returns subject/SAN/validity/thumbprint and a boolean
        HasPrivateKey flag; the private key itself is never read or
        exported (FLEXERA-IIS-BASELINE.md section 4, SECURITY-AUDIT.md
        section 11).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CertificateHash,
        [string]$StoreName = 'My'
    )

    if ([string]::IsNullOrWhiteSpace($CertificateHash)) { return $null }

    try {
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\$StoreName" -ErrorAction Stop |
            Where-Object { $_.Thumbprint -eq $CertificateHash } |
            Select-Object -First 1
    } catch {
        return $null
    }

    if (-not $cert) { return $null }

    $sanNames = @()
    try {
        $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' } | Select-Object -First 1
        if ($sanExtension) {
            $sanNames = @(
                ($sanExtension.Format($false) -split ',') |
                    ForEach-Object { ($_ -replace '^[^=]+=', '').Trim() } |
                    Where-Object { $_ }
            )
        }
    } catch {
        # SAN parsing is best-effort; an unparsable extension just yields no SAN names.
        $sanNames = @()
    }

    [pscustomobject]@{
        Thumbprint      = $cert.Thumbprint
        Subject         = $cert.Subject
        Issuer          = $cert.Issuer
        NotBefore       = $cert.NotBefore
        NotAfter        = $cert.NotAfter
        SubjectAltNames = $sanNames
        HasPrivateKey   = $cert.HasPrivateKey
    }
}

function Get-IisAppPoolInfo {
    <#
        Reads AppPool configuration via Get-WebConfiguration against the
        "MACHINE/WEBROOT/APPHOST" configuration path rather than the
        IIS:\AppPools\<name> drive path - the config-path string form
        does not depend on the WebAdministration PSProvider, so it works
        under PowerShell 7's compatibility layer where IIS:\ does not
        (see Import-WebAdministrationModule). Runtime state (Started/
        Stopped) is not part of applicationHost.config, so it is read
        separately via Get-WebAppPoolState.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    Import-WebAdministrationModule

    $escapedName = $Name.Replace("'", "''")
    $pool = Get-WebConfiguration -Filter "system.applicationHost/applicationPools/add[@name='$escapedName']" -PSPath 'MACHINE/WEBROOT/APPHOST' -ErrorAction Stop
    if (-not $pool) { throw "Application Pool '$Name' not found." }

    $state = $null
    try { $state = (Get-WebAppPoolState -Name $Name -ErrorAction Stop).Value }
    catch { $state = $null }

    [pscustomobject]@{
        Name            = $Name
        State           = $state
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

    if ($PSVersionTable.PSEdition -eq 'Core') {
        $warnings.Add("Running under PowerShell $($PSVersionTable.PSVersion) (Core edition). This project targets Windows PowerShell 5.1 first (SPECIFICATION.md section 4); the WebAdministration module runs through PowerShell 7's Windows PowerShell compatibility layer and some cmdlets (e.g. Get-WebApplication, Get-WebVirtualDirectory) can fail there without an obvious symptom. If discovery finds nothing on a server known to have IIS/Flexera configured, retry under powershell.exe (Windows PowerShell 5.1) before assuming the topology itself is the problem.")
    }

    $endpoints = @()
    $discoveryWarnings = @()
    try {
        $endpoints = @(Get-IisFlexeraEndpoints -KnownEndpointNames $KnownEndpointNames -SiteName $SiteName -AppPoolName $AppPoolName -WarningVariable discoveryWarnings)
    } catch {
        $warnings.Add("Flexera endpoint discovery failed: $($_.Exception.Message)")
    }
    foreach ($dw in $discoveryWarnings) { $warnings.Add("Endpoint discovery: $dw") }

    $resolvedPools = @($endpoints | Where-Object { $_.AppPoolName } | Select-Object -ExpandProperty AppPoolName -Unique)

    if (-not $resolvedPools -and $AppPoolName) {
        $resolvedPools = @($AppPoolName)
        $warnings.Add("No known Flexera endpoint (ManageSoftRL/ManageSoftDL) was discovered; using explicitly supplied -AppPoolName '$AppPoolName'.")
    }

    if (-not $resolvedPools) {
        $diagnostic = if ($warnings.Count -gt 0) { " Diagnostic warnings collected during discovery: " + ($warnings -join ' | ') } else { '' }
        throw "Unable to determine which Application Pool serves Flexera traffic. No ManageSoftRL/ManageSoftDL endpoint was found and no -SiteName/-AppPoolName override was supplied. Refusing to start an unattended run against an ambiguous target.$diagnostic"
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
        Endpoints        = @($endpoints)
        SelectedSites    = $siteInfo.ToArray()
        SelectedAppPools = $poolInfo.ToArray()
        Warnings         = @($warnings)
    }
}
