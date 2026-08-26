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

    Pass -Date to restrict the report to a single calendar day in the
    selected -DateTimeZoneId (analyzer-local timezone by default), filtering
    against DST-aware UTC boundaries for requests, counters, worker samples and
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
    [string]$Date,
    [ValidateSet('UTC', 'Local', 'Both')][string]$DisplayTimeZone = 'UTC',
    [string]$DateTimeZoneId
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'src/Time.ps1')
. (Join-Path $PSScriptRoot 'src/InputData.ps1')
. (Join-Path $PSScriptRoot 'src/IisLogs.ps1')
. (Join-Path $PSScriptRoot 'src/Statistics.ps1')
. (Join-Path $PSScriptRoot 'src/Reporting.ps1')

if (-not (Test-Path -LiteralPath $RunPath)) {
    throw "Run path not found: $RunPath"
}

$metadataInput = Import-CollectionJson -Path (Join-Path $RunPath 'metadata.json')
$counterInput = Import-CollectionCsv -Path (Join-Path $RunPath 'iis-counters.csv')
$workerInput = Import-CollectionCsv -Path (Join-Path $RunPath 'worker-processes.csv')
$appPoolEventInput = Import-CollectionCsv -Path (Join-Path $RunPath 'apppool-events.csv')
$securityInput = Import-CollectionJson -Path (Join-Path $RunPath 'security-audit.json')
$baselineInput = Import-CollectionJson -Path (Join-Path $RunPath 'configuration-baseline.json')

$metadata = $metadataInput.Data
$counters = @($counterInput.Records)
$workerSamples = @($workerInput.Records)
$appPoolEvents = @($appPoolEventInput.Records)
$securityControls = if ($securityInput.Status -eq 'PRESENT') { @($securityInput.Data) } else { @() }
$configBaseline = $baselineInput.Data
$dataQuality = @($metadataInput, $counterInput, $workerInput, $appPoolEventInput, $securityInput, $baselineInput)

$reportTimeZone = [TimeZoneInfo]::Local
if ($DateTimeZoneId) {
    try { $reportTimeZone = [TimeZoneInfo]::FindSystemTimeZoneById($DateTimeZoneId) }
    catch { throw "Unknown -DateTimeZoneId '$DateTimeZoneId': $($_.Exception.Message)" }
}

$dayWarnings = New-Object System.Collections.Generic.List[string]
$targetDate = $null
if ($Date) {
    try {
        $targetDate = [datetime]::Parse($Date, [System.Globalization.CultureInfo]::InvariantCulture)
    } catch {
        throw "Could not parse -Date '$Date' as a date: $($_.Exception.Message)"
    }

    $countersBeforeFilter = $counters.Count
    $workersBeforeFilter = $workerSamples.Count
    $eventsBeforeFilter = $appPoolEvents.Count
    $counters      = @(Select-ByDate -Records $counters -TimestampProperty 'Timestamp' -Date $targetDate -TimeZone $reportTimeZone)
    $workerSamples = @(Select-ByDate -Records $workerSamples -TimestampProperty 'Timestamp' -Date $targetDate -TimeZone $reportTimeZone)
    $appPoolEvents = @(Select-ByDate -Records $appPoolEvents -TimestampProperty 'Timestamp' -Date $targetDate -TimeZone $reportTimeZone)

    $dayWarnings.Add("Report restricted to $($targetDate.ToString('yyyy-MM-dd')) in timezone '$($reportTimeZone.Id)'; filtering used UTC boundaries.") | Out-Null
    if ($counters.Count -eq 0 -and $countersBeforeFilter -gt 0) { $counterInput.Status = 'OUTSIDE_PERIOD' }
    if ($workerSamples.Count -eq 0 -and $workersBeforeFilter -gt 0) { $workerInput.Status = 'OUTSIDE_PERIOD' }
    if ($appPoolEvents.Count -eq 0 -and $eventsBeforeFilter -gt 0) { $appPoolEventInput.Status = 'OUTSIDE_PERIOD' }
}

$requests = @()
$logWarnings = New-Object System.Collections.Generic.List[string]

if ($LogPath) {
    # File timestamps are local filesystem metadata while W3C rows are UTC, so
    # -SinceDate here is only a conservative pre-filter over which *files* get
    # parsed at all (see Get-W3CLogFileSet) - it never drops a file that could
    # plausibly contain the target day. The authoritative UTC window is still
    # applied to normalized records below via Select-ByDate. Without this,
    # -Date would still parse every rotated log file in -LogPath into memory
    # before discarding all but one day's worth of records.
    $logSetParams = @{ Path = $LogPath }
    if ($targetDate) { $logSetParams['SinceDate'] = $targetDate }
    $logSet = Read-W3CLogSet @logSetParams
    if (-not $logSet.FieldsConsistent) {
        $logWarnings.Add('IIS log files in this run use inconsistent #Fields: definitions; each file was parsed against its own header, but column sets differ across files.') | Out-Null
    }
    if ($logSet.MalformedCount -gt 0) {
        $logWarnings.Add("Skipped $($logSet.MalformedCount) malformed IIS log row(s).") | Out-Null
    }
    foreach ($unreadable in @($logSet.UnreadableFiles)) {
        $logWarnings.Add("Could not read IIS log file '$($unreadable.Path)': $($unreadable.Error)") | Out-Null
    }
    $normalizedRequests = New-Object System.Collections.Generic.List[object]
    foreach ($record in $logSet.Records) {
        $normalizedRequests.Add((ConvertTo-NormalizedRequestRecord -Record $record)) | Out-Null
    }
    $requests = @($normalizedRequests)
    $logInputStatus = if ($requests.Count -gt 0) { 'PRESENT' } elseif (@($logSet.UnreadableFiles).Count -gt 0) { 'INVALID' } else { 'EMPTY' }

    if ($targetDate) {
        $requests = @(Select-ByDate -Records $requests -TimestampProperty 'Timestamp' -Date $targetDate -TimeZone $reportTimeZone -UnspecifiedKind UnspecifiedAsUtc)
        if ($requests.Count -eq 0) {
            if ($logSet.Records.Count -gt 0) { $logInputStatus = 'OUTSIDE_PERIOD' }
            $dayWarnings.Add("No HTTP requests fall on $($targetDate.ToString('yyyy-MM-dd')) in the supplied -LogPath; check the selected timezone and log files.") | Out-Null
        }
    }
    $logInputError = if ($logInputStatus -eq 'INVALID') { @($logSet.UnreadableFiles | ForEach-Object { $_.Error }) -join '; ' } else { $null }
    $dataQuality += [pscustomobject]@{ Path = ($LogPath -join ';'); Status = $logInputStatus; Error = $logInputError }
} else {
    $logWarnings.Add('No -LogPath supplied; HTTP traffic/latency analysis is unavailable for this report.') | Out-Null
    $dataQuality += [pscustomobject]@{ Path = 'IIS W3C logs'; Status = 'ABSENT'; Error = $null }
}

$cpuValues          = @($workerSamples | Where-Object { $null -ne $_.CPUPercent -and $_.CPUPercent -ne '' } | ForEach-Object { [double]$_.CPUPercent })
$privateBytesValues = @($workerSamples | Where-Object { $null -ne $_.PrivateBytes -and $_.PrivateBytes -ne '' } | ForEach-Object { [double]$_.PrivateBytes })
$queueValues        = @($counters | Where-Object { $null -ne $_.QueueSize -and $_.QueueSize -ne '' } | ForEach-Object { [double]$_.QueueSize })
$connectionValues   = @($counters | Where-Object { $null -ne $_.CurrentConnections -and $_.CurrentConnections -ne '' } | ForEach-Object { [double]$_.CurrentConnections })

$rejectedMeasure = $counters | Where-Object { $null -ne $_.RejectedRequests -and $_.RejectedRequests -ne '' } | ForEach-Object { [double]$_.RejectedRequests } | Measure-Object -Maximum
$rejectedTotal = if ($rejectedMeasure) { $rejectedMeasure.Maximum } else { $null }

$latencyValues = @($requests | Where-Object { $null -ne $_.TimeTakenMs } | ForEach-Object { $_.TimeTakenMs })
$statusBreakdown = Get-ResponseStatusBreakdown -Records $requests
$endpointStats = @(Group-RequestsByEndpoint -Records $requests | Sort-Object RequestCount -Descending)
$http405 = Get-Http405Analysis -Records $requests
$transferAnalysis = @(Get-TransferAnalysis -Records $requests)
$correlationTimeline = @(Get-IisCorrelationTimeline -Requests $requests -WorkerSamples $workerSamples -CounterSamples $counters -AppPoolEvents $appPoolEvents)

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
    Http405Analysis         = $http405
    TransferAnalysis        = $transferAnalysis
    DataQuality             = $dataQuality
    DisplayTimeZone         = $DisplayTimeZone
    ReportTimeZone          = $reportTimeZone.Id
    CorrelationTimeline     = $correlationTimeline
}

$summaryPath = Join-Path $RunPath 'summary.json'
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath -Encoding UTF8

$reportPath = Join-Path $RunPath 'report.md'
New-CollectionReport -Summary $summary -Path $reportPath

Write-Host "Analysis complete. Report: $reportPath"
