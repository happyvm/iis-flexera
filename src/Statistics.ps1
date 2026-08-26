# Statistical helpers shared by the analyzer and the report generator.
#
# Flexera does not publish universal performance thresholds, so this file
# only computes observed statistics - it must never invent a pass/fail
# threshold (SPECIFICATION.md section 14.2, FLEXERA-IIS-BASELINE.md section 13).

function Select-ByDate {
    <#
        Filters records to a single calendar day [Date 00:00:00, Date+1
        00:00:00), reading the given property as either a [datetime] or
        a string PowerShell can cast to one (covers both normalized W3C
        request records and CSV rows Import-Csv loaded as strings).
        Records with a missing/unparsable timestamp are dropped rather
        than guessed into the window - they cannot be reliably attributed
        to a specific day.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)][string]$TimestampProperty,
        [Parameter(Mandatory)][datetime]$Date,
        [TimeZoneInfo]$TimeZone = [TimeZoneInfo]::Local,
        [ValidateSet('Utc', 'Local', 'UnspecifiedAsUtc')][string]$UnspecifiedKind = 'Utc'
    )

    $range = Get-UtcDayRange -Date $Date -TimeZone $TimeZone

    $Records | Where-Object {
        $raw = $_.$TimestampProperty
        if (-not $raw) { return $false }

        $ts = ConvertTo-UtcDateTime -Value $raw -UnspecifiedKind $UnspecifiedKind
        if ($null -eq $ts) { return $false }

        return ($ts -ge $range.StartUtc -and $ts -lt $range.EndUtc)
    }
}

function Get-Percentile {
    <#
        Nearest-rank percentile: rank = ceil(P/100 * N), 1-based, clamped
        to [1, N].
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][double[]]$Values,
        [Parameter(Mandatory)][ValidateRange(0, 100)][double]$Percentile
    )

    if (-not $Values -or $Values.Count -eq 0) { return $null }

    $sorted = @($Values | Sort-Object)
    $n = $sorted.Count

    $rank = [math]::Ceiling(($Percentile / 100) * $n)
    if ($rank -lt 1) { $rank = 1 }
    if ($rank -gt $n) { $rank = $n }

    return $sorted[$rank - 1]
}

function Get-StatisticsSummary {
    <#
        Returns Count/Mean/Min/Max/P50/P90/P95/P99 for a numeric series.
        Returns Count = 0 and $null for the rest when there is no data,
        rather than fabricating a value.
    #>
    [CmdletBinding()]
    param(
        [double[]]$Values
    )

    if (-not $Values -or $Values.Count -eq 0) {
        return [pscustomobject]@{
            Count = 0; Mean = $null; Min = $null; Max = $null
            P50 = $null; P90 = $null; P95 = $null; P99 = $null
        }
    }

    $sorted = @($Values | Sort-Object)
    $sum = 0.0
    foreach ($v in $sorted) { $sum += $v }

    [pscustomobject]@{
        Count = $sorted.Count
        Mean  = [math]::Round($sum / $sorted.Count, 4)
        Min   = $sorted[0]
        Max   = $sorted[-1]
        P50   = Get-Percentile -Values $sorted -Percentile 50
        P90   = Get-Percentile -Values $sorted -Percentile 90
        P95   = Get-Percentile -Values $sorted -Percentile 95
        P99   = Get-Percentile -Values $sorted -Percentile 99
    }
}

function Get-HttpStatusClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$StatusCode
    )

    switch ($StatusCode) {
        { $_ -ge 200 -and $_ -lt 300 } { return '2xx' }
        { $_ -ge 300 -and $_ -lt 400 } { return '3xx' }
        { $_ -ge 400 -and $_ -lt 500 } { return '4xx' }
        { $_ -ge 500 -and $_ -lt 600 } { return '5xx' }
        default { return 'Other' }
    }
}

function Get-ResponseStatusBreakdown {
    <#
        Counts/percentages by 2xx-5xx class, plus the most frequent exact
        status.substatus combinations (SPECIFICATION.md section 10.2).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records
    )

    $withStatus = @($Records | Where-Object { $null -ne $_.StatusCode })
    $total = $withStatus.Count

    $byClass = [ordered]@{}
    foreach ($cls in '2xx', '3xx', '4xx', '5xx', 'Other') { $byClass[$cls] = 0 }

    foreach ($r in $withStatus) {
        $cls = Get-HttpStatusClass -StatusCode $r.StatusCode
        $byClass[$cls]++
    }

    $classSummary = foreach ($cls in '2xx', '3xx', '4xx', '5xx', 'Other') {
        $count = $byClass[$cls]
        $pct = if ($total -gt 0) { [math]::Round(($count / $total) * 100, 2) } else { 0 }
        [pscustomobject]@{ Class = $cls; Count = $count; Percentage = $pct }
    }

    $topCombos = $withStatus |
        Group-Object -Property {
            if ($null -ne $_.SubStatus) { "$($_.StatusCode).$($_.SubStatus)" } else { "$($_.StatusCode)" }
        } |
        Sort-Object Count -Descending |
        ForEach-Object { [pscustomobject]@{ StatusCombo = $_.Name; Count = $_.Count } }

    [pscustomobject]@{
        Total     = $total
        ByClass   = @($classSummary)
        TopCombos = @($topCombos)
    }
}

function Group-RequestsByEndpoint {
    <#
        Aggregates by cs-uri-stem only (no query string), per
        SPECIFICATION.md section 9.6.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records
    )

    $groups = $Records | Where-Object { $_.UriStem } | Group-Object -Property UriStem

    foreach ($g in $groups) {
        $latencies = @($g.Group | Where-Object { $null -ne $_.TimeTakenMs } | ForEach-Object { $_.TimeTakenMs })
        $errors = @($g.Group | Where-Object { $null -ne $_.StatusCode -and [int]$_.StatusCode -ge 400 }).Count

        $receivedMeasure = $g.Group | Where-Object { $null -ne $_.BytesReceived } | Measure-Object -Property BytesReceived -Sum
        $sentMeasure     = $g.Group | Where-Object { $null -ne $_.BytesSent } | Measure-Object -Property BytesSent -Sum

        $latencyStats = Get-StatisticsSummary -Values $latencies

        [pscustomobject]@{
            UriStem             = $g.Name
            FlexeraCategory     = Get-FlexeraEndpointCategory -UriStem $g.Name
            RequestCount        = $g.Count
            BytesReceived       = if ($receivedMeasure) { $receivedMeasure.Sum } else { $null }
            BytesSent           = if ($sentMeasure) { $sentMeasure.Sum } else { $null }
            LatencyP50          = $latencyStats.P50
            LatencyP90          = $latencyStats.P90
            LatencyP95          = $latencyStats.P95
            LatencyP99          = $latencyStats.P99
            LatencyMax          = $latencyStats.Max
            LatencySampleCount  = $latencyStats.Count
            ErrorCount          = $errors
            ErrorRatePercent    = if ($g.Count -gt 0) { [math]::Round(100 * $errors / $g.Count, 2) } else { 0 }
            Methods             = @(($g.Group | Where-Object { $_.Method } | Group-Object Method | Sort-Object Count -Descending) | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
            TopClients          = @(($g.Group | Where-Object { $_.ClientIp } | Group-Object ClientIp | Sort-Object Count -Descending | Select-Object -First 5) | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
        }
    }
}

function Get-FlexeraEndpointCategory {
    <# Classification is diagnostic metadata, not an assertion about server-side implementation. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UriStem,
        [System.Collections.IDictionary]$Classification = [ordered]@{
            'Agent configuration' = '(?i)/agent-configurations(?:/|$)'
            'Inventory settings' = '(?i)/InventorySettings(?:\.|/|$)'
            'Inventory upload' = '(?i)^/ManageSoftRL/'
            'Package/download service' = '(?i)^/ManageSoftDL/'
            'Inventory Beacon API' = '(?i)^/inventory-beacons/api/'
        }
    )

    foreach ($category in $Classification.Keys) {
        if ($UriStem -match $Classification[$category]) { return $category }
    }
    return 'Unclassified'
}

function Get-Http405Analysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records)

    $records405 = @($Records | Where-Object { $null -ne $_.StatusCode -and [int]$_.StatusCode -eq 405 })
    $total = @($Records).Count
    $toSummary = {
        param($Groups, [string[]]$Names)
        foreach ($group in $Groups) {
            $row = [ordered]@{}
            for ($i = 0; $i -lt $Names.Count; $i++) {
                $propertyName = $Names[$i]
                $row[$propertyName] = $group.Group[0].PSObject.Properties[$propertyName].Value
            }
            $row['Count'] = $group.Count
            $row['PercentageOf405'] = if ($records405.Count) { [math]::Round(100 * $group.Count / $records405.Count, 2) } else { 0 }
            $row['SubStatuses'] = @(($group.Group | Group-Object SubStatus, Win32Status | Sort-Object Count -Descending) | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
            [pscustomobject]$row
        }
    }

    $byMethod = & $toSummary ($records405 | Group-Object Method | Sort-Object Count -Descending) @('Method')
    $byEndpoint = & $toSummary ($records405 | Group-Object UriStem, Method | Sort-Object Count -Descending) @('UriStem', 'Method')
    $byClient = & $toSummary ($records405 | Where-Object ClientIp | Group-Object ClientIp, UriStem, Method | Sort-Object Count -Descending) @('ClientIp', 'UriStem', 'Method')
    # Group script-property names are not record properties, so expose the UTC
    # period explicitly for the timeline.
    $byHour = foreach ($g in ($records405 | Where-Object Timestamp | Group-Object { $_.Timestamp.ToString('yyyy-MM-ddTHH:00:00Z') } | Sort-Object Name)) {
        [pscustomobject]@{ PeriodUtc = $g.Name; Count = $g.Count; PercentageOf405 = if ($records405.Count) { [math]::Round(100 * $g.Count / $records405.Count, 2) } else { 0 } }
    }

    [pscustomobject]@{
        Count = $records405.Count
        PercentageOfAllRequests = if ($total) { [math]::Round(100 * $records405.Count / $total, 2) } else { 0 }
        ByMethod = @($byMethod)
        ByEndpoint = @($byEndpoint)
        ByClient = @($byClient)
        ByHourUtc = @($byHour)
    }
}

function Get-TransferAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records)

    foreach ($record in $Records) {
        $throughput = $null
        if ($null -ne $record.BytesSent -and $null -ne $record.TimeTakenMs -and [double]$record.TimeTakenMs -gt 0) {
            $throughput = [math]::Round(([double]$record.BytesSent * 1000) / [double]$record.TimeTakenMs, 2)
        }
        [pscustomobject]@{
            Timestamp = $record.Timestamp; UriStem = $record.UriStem; Method = $record.Method
            StatusCode = $record.StatusCode; ClientIp = $record.ClientIp
            TimeTakenMs = $record.TimeTakenMs; BytesSent = $record.BytesSent
            ThroughputBytesPerSecond = $throughput
        }
    }
}

function Get-IisCorrelationTimeline {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Requests = @(),
        [AllowEmptyCollection()][object[]]$WorkerSamples = @(),
        [AllowEmptyCollection()][object[]]$CounterSamples = @(),
        [AllowEmptyCollection()][object[]]$AppPoolEvents = @()
    )

    $buckets = @{}
    foreach ($source in @(
        [pscustomobject]@{ Name='Request'; Rows=$Requests },
        [pscustomobject]@{ Name='Worker'; Rows=$WorkerSamples },
        [pscustomobject]@{ Name='Counter'; Rows=$CounterSamples },
        [pscustomobject]@{ Name='Event'; Rows=$AppPoolEvents }
    )) {
        foreach ($row in @($source.Rows)) {
            $utc = ConvertTo-UtcDateTime -Value $row.Timestamp
            if ($null -eq $utc) { continue }
            $key = $utc.ToString('yyyy-MM-ddTHH:mm:00Z')
            if (-not $buckets.ContainsKey($key)) {
                $buckets[$key] = [pscustomobject]@{
                    Requests = New-Object System.Collections.Generic.List[object]
                    Workers = New-Object System.Collections.Generic.List[object]
                    Counters = New-Object System.Collections.Generic.List[object]
                    Events = New-Object System.Collections.Generic.List[object]
                }
            }
            switch ($source.Name) {
                Request { $buckets[$key].Requests.Add($row) | Out-Null }
                Worker { $buckets[$key].Workers.Add($row) | Out-Null }
                Counter { $buckets[$key].Counters.Add($row) | Out-Null }
                Event { $buckets[$key].Events.Add($row) | Out-Null }
            }
        }
    }

    foreach ($key in @($buckets.Keys | Sort-Object)) {
        $bucket = $buckets[$key]
        $latency = @($bucket.Requests | Where-Object { $null -ne $_.TimeTakenMs } | ForEach-Object { [double]$_.TimeTakenMs })
        $cpu = @($bucket.Workers | Where-Object { $null -ne $_.CPUPercent -and $_.CPUPercent -ne '' } | ForEach-Object { [double]$_.CPUPercent })
        $private = @($bucket.Workers | Where-Object { $null -ne $_.PrivateBytes -and $_.PrivateBytes -ne '' } | ForEach-Object { [double]$_.PrivateBytes })
        $queue = @($bucket.Counters | Where-Object { $null -ne $_.QueueSize -and $_.QueueSize -ne '' } | ForEach-Object { [double]$_.QueueSize })
        [pscustomobject]@{
            PeriodUtc = $key
            RequestCount = @($bucket.Requests).Count
            Http405Count = @($bucket.Requests | Where-Object { $_.StatusCode -eq 405 }).Count
            LatencyP95Ms = (Get-StatisticsSummary $latency).P95
            LatencyMaxMs = (Get-StatisticsSummary $latency).Max
            WorkerCpuMaxPercent = (Get-StatisticsSummary $cpu).Max
            WorkerPrivateBytesMax = (Get-StatisticsSummary $private).Max
            QueueSizeMax = (Get-StatisticsSummary $queue).Max
            AppPoolEvents = @($bucket.Events | ForEach-Object { "$($_.EventType):$($_.PID)$($_.PreviousPID)" }) -join ', '
        }
    }
}

function Get-RequestVolumeByPeriod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [ValidateSet('Hour', 'Day')][string]$Granularity = 'Hour'
    )

    $withTimestamp = $Records | Where-Object { $null -ne $_.Timestamp }

    $groups = if ($Granularity -eq 'Day') {
        $withTimestamp | Group-Object -Property { $_.Timestamp.ToString('yyyy-MM-dd') }
    } else {
        $withTimestamp | Group-Object -Property { $_.Timestamp.ToString('yyyy-MM-ddTHH:00:00Z') }
    }

    $groups | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Period = $_.Name; RequestCount = $_.Count }
    }
}
