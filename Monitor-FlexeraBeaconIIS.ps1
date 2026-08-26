#Requires -Version 5.1
<#
    .SYNOPSIS
    Read-only IIS/Flexera preflight, security audit and timed performance
    collector for the IIS workload of a Flexera Inventory Beacon.

    .DESCRIPTION
    See SPECIFICATION.md, FLEXERA-IIS-BASELINE.md, SECURITY-AUDIT.md and
    AGENTS.md for the normative behavior this script implements. It never
    restarts IIS, recycles an Application Pool, or changes IIS/Flexera
    configuration (SPECIFICATION.md section 15).

    .EXAMPLE
    .\Monitor-FlexeraBeaconIIS.ps1 -Duration 00:10:00 -SampleIntervalSeconds 5
    A short validation run, per SPECIFICATION.md section 17.
#>
[CmdletBinding()]
param(
    [TimeSpan]$Duration = (New-TimeSpan -Days 7),
    [int]$SampleIntervalSeconds = 15,
    [string]$OutputPath = (Join-Path (Get-Location) 'output'),
    [string]$SiteName,
    [string]$AppPoolName
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'src/Time.ps1')
. (Join-Path $PSScriptRoot 'src/Discovery.ps1')
. (Join-Path $PSScriptRoot 'src/WorkerProcess.ps1')
. (Join-Path $PSScriptRoot 'src/PerformanceCounters.ps1')
. (Join-Path $PSScriptRoot 'src/ConfigurationBaseline.ps1')
. (Join-Path $PSScriptRoot 'src/SecurityAudit.ps1')

function New-RunDirectory {
    param([Parameter(Mandatory)][string]$BasePath)

    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $runPath = Join-Path $BasePath $stamp
    New-Item -Path $runPath -ItemType Directory -Force | Out-Null
    return $runPath
}

function New-CsvStreamWriter {
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $utf8WithBom = New-Object System.Text.UTF8Encoding -ArgumentList $true
    [pscustomobject]@{
        Writer = New-Object System.IO.StreamWriter -ArgumentList $Path, $false, $utf8WithBom
        HeaderWritten = $false
    }
}

function Write-CsvStreamRecord {
    param(
        [Parameter(Mandatory)][object]$CsvWriter,
        [Parameter(Mandatory)][object[]]$Record
    )

    foreach ($item in $Record) {
        $lines = @($item | ConvertTo-Csv -NoTypeInformation)
        $startIndex = if ($CsvWriter.HeaderWritten) { 1 } else { 0 }
        for ($i = $startIndex; $i -lt $lines.Count; $i++) {
            $CsvWriter.Writer.WriteLine($lines[$i])
        }
        $CsvWriter.HeaderWritten = $true
    }
    # Preserve the previous per-write durability guarantee without closing and
    # reopening the file (important on servers with on-access antivirus).
    $CsvWriter.Writer.Flush()
}

function Write-CollectorEvent {
    param(
        [Parameter(Mandatory)][object]$CsvWriter,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )

    Write-CsvStreamRecord -CsvWriter $CsvWriter -Record @([pscustomobject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Level     = $Level
        Message   = $Message
    })
}

function Close-CsvStreamWriters {
    param([Parameter(Mandatory)][hashtable]$CsvWriters)
    foreach ($csvWriter in $CsvWriters.Values) {
        if ($csvWriter -and $csvWriter.Writer) { $csvWriter.Writer.Dispose() }
    }
}

Write-Host 'Starting Flexera Beacon IIS collector...'

if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Warning "Running under PowerShell $($PSVersionTable.PSVersion) (Core edition). This project targets Windows PowerShell 5.1 first; the WebAdministration module runs through PowerShell 7's Windows PowerShell compatibility layer, which can make discovery cmdlets fail silently. If discovery reports no Flexera endpoint on a server known to have one, retry under powershell.exe (Windows PowerShell 5.1) before assuming the topology itself is the problem."
}

$runPath = New-RunDirectory -BasePath $OutputPath
$collectorEventsPath   = Join-Path $runPath 'collector-events.csv'
$countersPath          = Join-Path $runPath 'iis-counters.csv'
$workerProcessesPath   = Join-Path $runPath 'worker-processes.csv'
$appPoolEventsPath     = Join-Path $runPath 'apppool-events.csv'
$metadataPath          = Join-Path $runPath 'metadata.json'
$baselinePath          = Join-Path $runPath 'configuration-baseline.json'
$securityAuditJsonPath = Join-Path $runPath 'security-audit.json'
$securityAuditCsvPath  = Join-Path $runPath 'security-audit.csv'

$csvWriters = @{
    CollectorEvents = New-CsvStreamWriter -Path $collectorEventsPath
    Counters        = New-CsvStreamWriter -Path $countersPath
    WorkerProcesses = New-CsvStreamWriter -Path $workerProcessesPath
    AppPoolEvents   = New-CsvStreamWriter -Path $appPoolEventsPath
}

Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'INFO' -Message "Run directory created: $runPath"

# --- Preflight: discovery, configuration baseline, security audit -------
# (FLEXERA-IIS-BASELINE.md section 15). A failed/ambiguous discovery
# terminates the run rather than silently monitoring the wrong pool.

$topology = $null
try {
    $topology = Invoke-FlexeraIisDiscovery -SiteName $SiteName -AppPoolName $AppPoolName
} catch {
    Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'FATAL' -Message "Discovery failed: $($_.Exception.Message)"
    Close-CsvStreamWriters -CsvWriters $csvWriters
    throw
}

foreach ($w in @($topology.Warnings)) {
    Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message $w
}

$baseline = $null
try {
    $baseline = New-FlexeraConfigurationBaseline -Topology $topology
    $baseline | ConvertTo-Json -Depth 8 | Set-Content -Path $baselinePath -Encoding UTF8
} catch {
    Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message "Configuration baseline capture failed: $($_.Exception.Message)"
}

# Log-field completeness preflight (SPECIFICATION.md section 16): explain
# which analyses will be unavailable rather than silently fabricating them
# once the run finishes.
foreach ($siteLogging in @($baseline.Logging)) {
    if ($siteLogging.AllRequiredFieldsPresent) { continue }

    foreach ($missing in @($siteLogging.MissingFields)) {
        Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message "Site '$($siteLogging.SiteName)' W3C logging is missing field '$($missing.Field)': $($missing.Impact)."
    }
}

try {
    # Wrapping the call in @() matters: PowerShell collapses a function's
    # empty-array return into $null for the caller, and $null would fail
    # Export-SecurityAuditCsv's mandatory -Controls binding below.
    $securityControls = @(Invoke-FlexeraSecurityAudit -Topology $topology -Baseline $baseline)
    $securityControls | ConvertTo-Json -Depth 8 | Set-Content -Path $securityAuditJsonPath -Encoding UTF8
    Export-SecurityAuditCsv -Controls $securityControls -Path $securityAuditCsvPath
} catch {
    Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message "Security audit failed: $($_.Exception.Message)"
}

$metadata = [pscustomobject]@{
    schemaVersion        = 2
    toolVersion          = '0.2.0'
    computerName         = $env:COMPUTERNAME
    collectionStart      = (Get-Date).ToUniversalTime().ToString('o')
    collectionEnd        = $null
    sampleIntervalSeconds = $SampleIntervalSeconds
    durationRequested    = $Duration.ToString()
    iis = [pscustomobject]@{
        version          = $topology.IisVersion
        sites            = $topology.SelectedSites
        applicationPools = $topology.SelectedAppPools
        endpoints        = $topology.Endpoints
    }
    logSources = @()
    warnings   = @($topology.Warnings)
}
$metadata | ConvertTo-Json -Depth 8 | Set-Content -Path $metadataPath -Encoding UTF8

# --- Timed sampling loop --------------------------------------------------

$appPoolNames = @($topology.SelectedAppPools | Select-Object -ExpandProperty Name)
$sitePoolPairs = @(Get-IisSiteAppPoolPairs -Endpoints @($topology.Endpoints) -Sites @($topology.SelectedSites) -AppPoolNames $appPoolNames)
$previousMap = @()
$errorCount = 0
$startTime = Get-Date
$endTime = $startTime.Add($Duration)

Write-Host "Collecting for $Duration (interval: ${SampleIntervalSeconds}s). Output: $runPath"

while ((Get-Date) -lt $endTime) {
    $tickStart = Get-Date
    $tickStartUtc = $tickStart.ToUniversalTime()

    try {
        # @() matters here too: zero worker processes for every tracked
        # AppPool is valid (SPECIFICATION.md section 6.3), but PowerShell
        # would otherwise collapse that empty result to $null, and
        # Update-WorkerProcessTracking's mandatory -CurrentMap would then
        # throw on every tick.
        $currentMap = @(Get-WorkerProcessMap)
        $events = @(Update-WorkerProcessTracking -AppPoolNames $appPoolNames -CurrentMap $currentMap -PreviousMap $previousMap)
        if ($events.Count -gt 0) {
            Write-CsvStreamRecord -CsvWriter $csvWriters.AppPoolEvents -Record $events
        }
        $previousMap = $currentMap

        $trackedPids = @($currentMap | Where-Object { $_.AppPoolName -in $appPoolNames } | Select-Object -ExpandProperty PID -Unique)
        $workerSamplesByPid = @{}
        foreach ($sample in @(Get-WorkerProcessCounterSamples -ProcessId $trackedPids)) {
            $workerSamplesByPid[[int]$sample.PID] = $sample
        }

        foreach ($poolName in $appPoolNames) {
            $poolPids = @($currentMap | Where-Object { $_.AppPoolName -eq $poolName } | Select-Object -ExpandProperty PID)
            $workerCount = $poolPids.Count

            foreach ($processId in $poolPids) {
                try {
                    $wp = $workerSamplesByPid[[int]$processId]
                    if ($wp) {
                        $row = [pscustomobject]@{
                            Timestamp       = $tickStartUtc.ToString('o')
                            AppPoolName     = $poolName
                            PID             = $wp.PID
                            CPUPercent      = $wp.CPUPercent
                            RawCPUPercent   = $wp.RawCPUPercent
                            WorkingSetBytes = $wp.WorkingSetBytes
                            PrivateBytes    = $wp.PrivateBytes
                            ThreadCount     = $wp.ThreadCount
                            HandleCount     = $wp.HandleCount
                            VirtualBytes    = $wp.VirtualBytes
                            UptimeSeconds   = $wp.UptimeSeconds
                            StartTimeUtc    = if ($wp.StartTimeUtc) { $wp.StartTimeUtc.ToString('o') } else { $null }
                            CpuTotalSeconds = $wp.CpuTotalSeconds
                            WorkerCountForPool = $workerCount
                        }
                        Write-CsvStreamRecord -CsvWriter $csvWriters.WorkerProcesses -Record @($row)
                    }
                } catch {
                    $errorCount++
                    Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message "Worker-process sample failed for PID $processId : $($_.Exception.Message)"
                }
            }
        }

        # Web Service counters are site-scoped and request-queue counters are
        # pool-scoped. Sample each unique instance once, then compose rows.
        $webSamplesBySite = @{}
        foreach ($siteNameForCounter in @($sitePoolPairs | Select-Object -ExpandProperty SiteName -Unique)) {
            $webSamplesBySite[$siteNameForCounter] = Get-WebServiceSample -SiteCounterInstance $siteNameForCounter
        }
        $queueSamplesByPool = @{}
        foreach ($poolName in $appPoolNames) {
            $queueSamplesByPool[$poolName] = Get-HttpSysQueueSample -QueueInstance $poolName
        }

        foreach ($pair in $sitePoolPairs) {
                try {
                    $webSample = $webSamplesBySite[$pair.SiteName]
                    $queueSample = $queueSamplesByPool[$pair.AppPoolName]
                    $row = [pscustomobject]@{
                        Timestamp                = $tickStartUtc.ToString('o')
                        SiteName                 = $pair.SiteName
                        AppPoolName              = $pair.AppPoolName
                        CurrentConnections       = $webSample.CurrentConnections
                        ConnectionAttemptsPerSec = $webSample.ConnectionAttemptsPerSec
                        RequestsPerSec           = $webSample.TotalMethodRequestsPerSec
                        BytesReceivedPerSec      = $webSample.BytesReceivedPerSec
                        BytesSentPerSec          = $webSample.BytesSentPerSec
                        QueueSize                = $queueSample.CurrentQueueSize
                        RejectedRequests         = $queueSample.RejectedRequests
                        ArrivalRate              = $queueSample.ArrivalRate
                        MaximumConnections       = $webSample.MaximumConnections
                        CurrentAnonymousUsers    = $webSample.CurrentAnonymousUsers
                        CurrentNonAnonymousUsers = $webSample.CurrentNonAnonymousUsers
                        ServiceUptimeSeconds     = $webSample.ServiceUptimeSeconds
                        CacheHitRate             = $queueSample.CacheHitRate
                        MaxQueueItemAge          = $queueSample.MaxQueueItemAge
                        ActiveRequests           = $queueSample.ActiveRequests
                    }
                    Write-CsvStreamRecord -CsvWriter $csvWriters.Counters -Record @($row)
                } catch {
                    $errorCount++
                    Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message "Counter sample failed for site '$($pair.SiteName)' and pool '$($pair.AppPoolName)': $($_.Exception.Message)"
                }
        }
    } catch {
        $errorCount++
        Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'WARNING' -Message "Sampling tick failed: $($_.Exception.Message)"
    }

    $elapsed = (Get-Date) - $tickStart
    $sleepSeconds = $SampleIntervalSeconds - $elapsed.TotalSeconds
    if ($sleepSeconds -gt 0) {
        Start-Sleep -Seconds $sleepSeconds
    }
}

$metadata.collectionEnd = (Get-Date).ToUniversalTime().ToString('o')
$metadata | ConvertTo-Json -Depth 8 | Set-Content -Path $metadataPath -Encoding UTF8

Write-CollectorEvent -CsvWriter $csvWriters.CollectorEvents -Level 'INFO' -Message "Collection finished. Collector errors: $errorCount"
Close-CsvStreamWriters -CsvWriters $csvWriters
Write-Host "Collection complete. Errors: $errorCount. Output: $runPath"
Write-Host "Run .\Analyze-FlexeraBeaconIIS.ps1 -RunPath '$runPath' -LogPath <iis-log-path> to generate the report."
