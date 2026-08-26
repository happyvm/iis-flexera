#Requires -Version 5.1
<#
    .SYNOPSIS
    Parses IIS W3C logs and the CSV/JSON output of a Monitor-FlexeraBeaconIIS.ps1
    run, then generates summary.json and report.md for that run.

    .DESCRIPTION
    Raw IIS logs are not copied by default (SPECIFICATION.md section 12);
    pass their location(s) via -LogPath. Without -LogPath, HTTP traffic and
    latency analysis is unavailable and the report says so explicitly
    rather than fabricating figures (SPECIFICATION.md section 16).

    Pass -Date to restrict the report to a single calendar day (local
    time), filtering requests, counters, worker-process samples and
    AppPool events alike. Useful both to re-analyze one day out of a
    multi-day Monitor-FlexeraBeaconIIS.ps1 run, and to analyze IIS's own
    daily-rotated W3C logs for a single past day without ever running the
    collector - point -LogPath at that day's log file(s) directly.
    Records with no resolvable timestamp are dropped rather than guessed
    into the window.

    .EXAMPLE
    .\Analyze-FlexeraBeaconIIS.ps1 -RunPath .\output\2026-08-26_081500 -LogPath 'C:\inetpub\logs\LogFiles\W3SVC1'

    .EXAMPLE
    .\Analyze-FlexeraBeaconIIS.ps1 -RunPath .\output\2026-08-26_081500 -LogPath 'C:\inetpub\logs\LogFiles\W3SVC1' -Date 2026-08-25
    Restricts the report to 2026-08-25 only, out of a longer run/log set.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunPath,
    [string[]]$LogPath,
    [string]$Date
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'src/IisLogs.ps1')
. (Join-Path $PSScriptRoot 'src/Statistics.ps1')
. (Join-Path $PSScriptRoot 'src/Reporting.ps1')

if (-not (Test-Path -LiteralPath $RunPath)) {
    throw "Run path not found: $RunPath"
}

$metadataPath = Join-Path $RunPath 'metadata.json'
$metadata = $null
if (Test-Path -LiteralPath $metadataPath) {
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
}

$counters = @()
$countersPath = Join-Path $RunPath 'iis-counters.csv'
if (Test-Path -LiteralPath $countersPath) {
    $counters = @(Import-Csv -LiteralPath $countersPath)
}

$workerSamples = @()
$workerPath = Join-Path $RunPath 'worker-processes.csv'
if (Test-Path -LiteralPath $workerPath) {
    $workerSamples = @(Import-Csv -LiteralPath $workerPath)
}

$appPoolEvents = @()
$appPoolEventsPath = Join-Path $RunPath 'apppool-events.csv'
if (Test-Path -LiteralPath $appPoolEventsPath) {
    $appPoolEvents = @(Import-Csv -LiteralPath $appPoolEventsPath)
}

$securityControls = @()
$securityAuditPath = Join-Path $RunPath 'security-audit.json'
if (Test-Path -LiteralPath $securityAuditPath) {
    $securityControls = @(Get-Content -LiteralPath $securityAuditPath -Raw | ConvertFrom-Json)
}

$configBaseline = $null
$configBaselinePath = Join-Path $RunPath 'configuration-baseline.json'
if (Test-Path -LiteralPath $configBaselinePath) {
    $configBaseline = Get-Content -LiteralPath $configBaselinePath -Raw | ConvertFrom-Json
}

$dayWarnings = New-Object System.Collections.Generic.List[string]
$targetDate = $null
if ($Date) {
    try {
        $targetDate = [datetime]::Parse($Date, [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        throw "Could not parse -Date '$Date' as a date: $($_.Exception.Message)"
    }

    $counters      = @(Select-ByDate -Records $counters -TimestampProperty 'Timestamp' -Date $targetDate)
    $workerSamples = @(Select-ByDate -Records $workerSamples -TimestampProperty 'Timestamp' -Date $targetDate)
    $appPoolEvents = @(Select-ByDate -Records $appPoolEvents -TimestampProperty 'Timestamp' -Date $targetDate)

    $dayWarnings.Add("Report restricted to $($targetDate.ToString('yyyy-MM-dd')) (local time).") | Out-Null
    if ($counters.Count -eq 0) { $dayWarnings.Add("No iis-counters.csv rows fall on $($targetDate.ToString('yyyy-MM-dd')).") | Out-Null }
    if ($workerSamples.Count -eq 0) { $dayWarnings.Add("No worker-processes.csv rows fall on $($targetDate.ToString('yyyy-MM-dd')).") | Out-Null }
}

$requests = @()
$logWarnings = New-Object System.Collections.Generic.List[string]

if ($LogPath) {
    $logSet = Read-W3CLogSet -Path $LogPath
    if (-not $logSet.FieldsConsistent) {
        $logWarnings.Add('IIS log files in this run use inconsistent #Fields: definitions; each file was parsed against its own header, but column sets differ across files.') | Out-Null
    }
    if ($logSet.MalformedCount -gt 0) {
        $logWarnings.Add("Skipped $($logSet.MalformedCount) malformed IIS log row(s).") | Out-Null
    }
    $requests = @($logSet.Records | ForEach-Object { ConvertTo-NormalizedRequestRecord -Record $_ })

    if ($targetDate) {
        $requests = @(Select-ByDate -Records $requests -TimestampProperty 'Timestamp' -Date $targetDate)
        if ($requests.Count -eq 0) { $dayWarnings.Add("No HTTP requests fall on $($targetDate.ToString('yyyy-MM-dd')) in the supplied -LogPath; check that the right daily log file(s) were passed.") | Out-Null }
    }
} else {
    $logWarnings.Add('No -LogPath supplied; HTTP traffic/latency analysis is unavailable for this report.') | Out-Null
}

$cpuValues          = @($workerSamples | Where-Object { $_.CPUPercent } | ForEach-Object { [double]$_.CPUPercent })
$privateBytesValues = @($workerSamples | Where-Object { $_.PrivateBytes } | ForEach-Object { [double]$_.PrivateBytes })
$queueValues        = @($counters | Where-Object { $_.QueueSize } | ForEach-Object { [double]$_.QueueSize })
$connectionValues   = @($counters | Where-Object { $_.CurrentConnections } | ForEach-Object { [double]$_.CurrentConnections })

$rejectedMeasure = $counters | Where-Object { $_.RejectedRequests } | ForEach-Object { [double]$_.RejectedRequests } | Measure-Object -Maximum
$rejectedTotal = if ($rejectedMeasure) { $rejectedMeasure.Maximum } else { $null }

$latencyValues = @($requests | Where-Object { $null -ne $_.TimeTakenMs } | ForEach-Object { $_.TimeTakenMs })
$statusBreakdown = Get-ResponseStatusBreakdown -Records $requests
$endpointStats = @(Group-RequestsByEndpoint -Records $requests | Sort-Object RequestCount -Descending)

$recycleCount = @($appPoolEvents | Where-Object { $_.EventType -eq 'OverlappedRecycle' }).Count

$timestamps = @($requests | Where-Object { $null -ne $_.Timestamp } | ForEach-Object { $_.Timestamp })
$trafficGranularity = 'Hour'
if ($timestamps.Count -gt 0) {
    $spanHours = (($timestamps | Measure-Object -Maximum).Maximum - ($timestamps | Measure-Object -Minimum).Minimum).TotalHours
    if ($spanHours -gt 48) { $trafficGranularity = 'Day' }
}
$trafficByPeriod = @(Get-RequestVolumeByPeriod -Records $requests -Granularity $trafficGranularity)

$allWarnings = New-Object System.Collections.Generic.List[string]
foreach ($w in $dayWarnings) { $allWarnings.Add($w) | Out-Null }
foreach ($w in $logWarnings) { $allWarnings.Add($w) | Out-Null }
if ($metadata -and $metadata.warnings) {
    foreach ($w in @($metadata.warnings)) { $allWarnings.Add($w) | Out-Null }
}

$summary = [pscustomobject]@{
    Metadata               = $metadata
    DateFilter              = if ($targetDate) { $targetDate.ToString('yyyy-MM-dd') } else { $null }
    RequestCount           = $requests.Count
    LatencyStats           = Get-StatisticsSummary -Values $latencyValues
    CpuStats                = Get-StatisticsSummary -Values $cpuValues
    PrivateBytesStats       = Get-StatisticsSummary -Values $privateBytesValues
    QueueStats              = Get-StatisticsSummary -Values $queueValues
    ConnectionStats         = Get-StatisticsSummary -Values $connectionValues
    RejectedRequestsTotal   = $rejectedTotal
    StatusBreakdown         = $statusBreakdown
    TopEndpoints            = @($endpointStats | Select-Object -First 20)
    AppPoolRecycleCount     = $recycleCount
    Warnings                = @($allWarnings)
    SecurityControls        = $securityControls
    ConfigurationBaseline   = $configBaseline
    TrafficByPeriod         = $trafficByPeriod
    TrafficGranularity      = $trafficGranularity
}

$summaryPath = Join-Path $RunPath 'summary.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath -Encoding UTF8

$reportPath = Join-Path $RunPath 'report.md'
New-CollectionReport -Summary $summary -Path $reportPath

Write-Host "Analysis complete. Report: $reportPath"
