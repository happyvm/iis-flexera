Set-StrictMode -Version Latest

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
        [Parameter(Mandatory)][datetime]$Date
    )

    $dayStart = $Date.Date
    $dayEnd = $dayStart.AddDays(1)

    $Records | Where-Object {
        $raw = $_.$TimestampProperty
        if (-not $raw) { return $false }

        $ts = $null
        if ($raw -is [datetime]) {
            $ts = $raw
        } else {
            $parsed = [datetime]::MinValue
            if (-not [datetime]::TryParse("$raw", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
                return $false
            }
            $ts = $parsed
        }

        return ($ts -ge $dayStart -and $ts -lt $dayEnd)
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

        $receivedMeasure = $g.Group | Where-Object { $null -ne $_.BytesReceived } | Measure-Object -Property BytesReceived -Sum
        $sentMeasure     = $g.Group | Where-Object { $null -ne $_.BytesSent } | Measure-Object -Property BytesSent -Sum

        $latencyStats = Get-StatisticsSummary -Values $latencies

        [pscustomobject]@{
            UriStem             = $g.Name
            RequestCount        = $g.Count
            BytesReceived       = if ($receivedMeasure) { $receivedMeasure.Sum } else { $null }
            BytesSent           = if ($sentMeasure) { $sentMeasure.Sum } else { $null }
            LatencyP50          = $latencyStats.P50
            LatencyP95          = $latencyStats.P95
            LatencyP99          = $latencyStats.P99
            LatencyMax          = $latencyStats.Max
            LatencySampleCount  = $latencyStats.Count
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
        $withTimestamp | Group-Object -Property { $_.Timestamp.ToString('yyyy-MM-ddTHH:00:00') }
    }

    $groups | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Period = $_.Name; RequestCount = $_.Count }
    }
}
