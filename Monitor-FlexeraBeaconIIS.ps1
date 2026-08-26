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

function Write-CollectorEvent {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )

    $record = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Level     = $Level
        Message   = $Message
    }

    $exists = Test-Path -LiteralPath $Path
    $record | Export-Csv -Path $Path -NoTypeInformation -Append:$exists -Encoding UTF8
}

Write-Host 'Starting Flexera Beacon IIS collector...'

$runPath = New-RunDirectory -BasePath $OutputPath
$collectorEventsPath   = Join-Path $runPath 'collector-events.csv'
$countersPath          = Join-Path $runPath 'iis-counters.csv'
$workerProcessesPath   = Join-Path $runPath 'worker-processes.csv'
$appPoolEventsPath     = Join-Path $runPath 'apppool-events.csv'
$metadataPath          = Join-Path $runPath 'metadata.json'
$baselinePath          = Join-Path $runPath 'configuration-baseline.json'
$securityAuditJsonPath = Join-Path $runPath 'security-audit.json'
$securityAuditCsvPath  = Join-Path $runPath 'security-audit.csv'

Write-CollectorEvent -Path $collectorEventsPath -Level 'INFO' -Message "Run directory created: $runPath"

# --- Preflight: discovery, configuration baseline, security audit -------
# (FLEXERA-IIS-BASELINE.md section 15). A failed/ambiguous discovery
# terminates the run rather than silently monitoring the wrong pool.

$topology = $null
try {
    $topology = Invoke-FlexeraIisDiscovery -SiteName $SiteName -AppPoolName $AppPoolName
} catch {
    Write-CollectorEvent -Path $collectorEventsPath -Level 'FATAL' -Message "Discovery failed: $($_.Exception.Message)"
    throw
}

foreach ($w in @($topology.Warnings)) {
    Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message $w
}

$baseline = $null
try {
    $baseline = New-FlexeraConfigurationBaseline -Topology $topology
    $baseline | ConvertTo-Json -Depth 8 | Set-Content -Path $baselinePath -Encoding UTF8
} catch {
    Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message "Configuration baseline capture failed: $($_.Exception.Message)"
}

# Log-field completeness preflight (SPECIFICATION.md section 16): explain
# which analyses will be unavailable rather than silently fabricating them
# once the run finishes.
foreach ($siteLogging in @($baseline.Logging)) {
    if ($siteLogging.AllRequiredFieldsPresent) { continue }

    foreach ($missing in @($siteLogging.MissingFields)) {
        Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message "Site '$($siteLogging.SiteName)' W3C logging is missing field '$($missing.Field)': $($missing.Impact)."
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
    Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message "Security audit failed: $($_.Exception.Message)"
}

$metadata = [pscustomobject]@{
    schemaVersion        = 1
    toolVersion          = '0.1.0'
    computerName         = $env:COMPUTERNAME
    collectionStart      = (Get-Date).ToString('o')
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
$previousMap = @()
$errorCount = 0
$startTime = Get-Date
$endTime = $startTime.Add($Duration)

Write-Host "Collecting for $Duration (interval: ${SampleIntervalSeconds}s). Output: $runPath"

while ((Get-Date) -lt $endTime) {
    $tickStart = Get-Date

    try {
        # @() matters here too: zero worker processes for every tracked
        # AppPool is valid (SPECIFICATION.md section 6.3), but PowerShell
        # would otherwise collapse that empty result to $null, and
        # Update-WorkerProcessTracking's mandatory -CurrentMap would then
        # throw on every tick.
        $currentMap = @(Get-WorkerProcessMap)
        $events = @(Update-WorkerProcessTracking -AppPoolNames $appPoolNames -CurrentMap $currentMap -PreviousMap $previousMap)
        if ($events.Count -gt 0) {
            $exists = Test-Path -LiteralPath $appPoolEventsPath
            $events | Export-Csv -Path $appPoolEventsPath -NoTypeInformation -Append:$exists -Encoding UTF8
        }
        $previousMap = $currentMap

        foreach ($poolName in $appPoolNames) {
            $poolPids = @($currentMap | Where-Object { $_.AppPoolName -eq $poolName } | Select-Object -ExpandProperty PID)

            foreach ($processId in $poolPids) {
                try {
                    $wp = Get-WorkerProcessCounterSample -ProcessId $processId
                    if ($wp) {
                        $row = [pscustomobject]@{
                            Timestamp       = $tickStart.ToString('o')
                            AppPoolName     = $poolName
                            PID             = $wp.PID
                            CPUPercent      = $wp.CPUPercent
                            RawCPUPercent   = $wp.RawCPUPercent
                            WorkingSetBytes = $wp.WorkingSetBytes
                            PrivateBytes    = $wp.PrivateBytes
                            ThreadCount     = $wp.ThreadCount
                            HandleCount     = $wp.HandleCount
                        }
                        $exists = Test-Path -LiteralPath $workerProcessesPath
                        $row | Export-Csv -Path $workerProcessesPath -NoTypeInformation -Append:$exists -Encoding UTF8
                    }
                } catch {
                    $errorCount++
                    Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message "Worker-process sample failed for PID $processId : $($_.Exception.Message)"
                }
            }

            foreach ($site in $topology.SelectedSites) {
                try {
                    $webSample = Get-WebServiceSample -SiteCounterInstance $site.Name
                    $queueSample = Get-HttpSysQueueSample -QueueInstance $poolName

                    $row = [pscustomobject]@{
                        Timestamp                = $tickStart.ToString('o')
                        SiteName                 = $site.Name
                        AppPoolName              = $poolName
                        CurrentConnections       = $webSample.CurrentConnections
                        ConnectionAttemptsPerSec = $webSample.ConnectionAttemptsPerSec
                        RequestsPerSec           = $webSample.TotalMethodRequestsPerSec
                        BytesReceivedPerSec      = $webSample.BytesReceivedPerSec
                        BytesSentPerSec          = $webSample.BytesSentPerSec
                        QueueSize                = $queueSample.CurrentQueueSize
                        RejectedRequests         = $queueSample.RejectedRequests
                        ArrivalRate              = $queueSample.ArrivalRate
                    }
                    $exists = Test-Path -LiteralPath $countersPath
                    $row | Export-Csv -Path $countersPath -NoTypeInformation -Append:$exists -Encoding UTF8
                } catch {
                    $errorCount++
                    Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message "Counter sample failed for site '$($site.Name)': $($_.Exception.Message)"
                }
            }
        }
    } catch {
        $errorCount++
        Write-CollectorEvent -Path $collectorEventsPath -Level 'WARNING' -Message "Sampling tick failed: $($_.Exception.Message)"
    }

    $elapsed = (Get-Date) - $tickStart
    $sleepSeconds = $SampleIntervalSeconds - $elapsed.TotalSeconds
    if ($sleepSeconds -gt 0) {
        Start-Sleep -Seconds $sleepSeconds
    }
}

$metadata.collectionEnd = (Get-Date).ToString('o')
$metadata | ConvertTo-Json -Depth 8 | Set-Content -Path $metadataPath -Encoding UTF8

Write-CollectorEvent -Path $collectorEventsPath -Level 'INFO' -Message "Collection finished. Collector errors: $errorCount"
Write-Host "Collection complete. Errors: $errorCount. Output: $runPath"
Write-Host "Run .\Analyze-FlexeraBeaconIIS.ps1 -RunPath '$runPath' -LogPath <iis-log-path> to generate the report."
