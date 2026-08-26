BeforeAll {
    . "$PSScriptRoot/../src/Statistics.ps1"
}

Describe 'Select-ByDate' {
    It 'keeps only records whose [datetime] timestamp falls on the given day' {
        $records = @(
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-19T23:59:00') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-20T00:00:00') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-20T12:00:00') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-21T00:00:00') }
        )
        $result = @(Select-ByDate -Records $records -TimestampProperty 'Timestamp' -Date (Get-Date '2026-08-20'))
        $result.Count | Should -Be 2
    }

    It 'parses a string timestamp column the way Import-Csv would provide it' {
        $records = @(
            [pscustomobject]@{ Timestamp = '2026-08-20T08:15:00.0000000+00:00' },
            [pscustomobject]@{ Timestamp = '2026-08-21T08:15:00.0000000+00:00' }
        )
        $result = @(Select-ByDate -Records $records -TimestampProperty 'Timestamp' -Date (Get-Date '2026-08-20'))
        $result.Count | Should -Be 1
    }

    It 'drops records with a missing timestamp rather than guessing' {
        $records = @(
            [pscustomobject]@{ Timestamp = $null },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-20T08:00:00') }
        )
        $result = @(Select-ByDate -Records $records -TimestampProperty 'Timestamp' -Date (Get-Date '2026-08-20'))
        $result.Count | Should -Be 1
    }

    It 'returns an empty result without throwing for an empty input' {
        { Select-ByDate -Records @() -TimestampProperty 'Timestamp' -Date (Get-Date '2026-08-20') } | Should -Not -Throw
        @(Select-ByDate -Records @() -TimestampProperty 'Timestamp' -Date (Get-Date '2026-08-20')).Count | Should -Be 0
    }
}

Describe 'Get-Percentile' {
    It 'returns $null for empty input' {
        Get-Percentile -Values @() -Percentile 95 | Should -BeNullOrEmpty
    }

    It 'computes P50 using nearest-rank on a simple ascending series' {
        Get-Percentile -Values (1..10) -Percentile 50 | Should -Be 5
    }

    It 'computes P95 using nearest-rank on a simple ascending series' {
        Get-Percentile -Values (1..100) -Percentile 95 | Should -Be 95
    }

    It 'clamps to the maximum for P100' {
        Get-Percentile -Values (1..10) -Percentile 100 | Should -Be 10
    }

    It 'does not require pre-sorted input' {
        Get-Percentile -Values @(30, 10, 20) -Percentile 50 | Should -Be 20
    }
}

Describe 'Get-StatisticsSummary' {
    It 'returns zero count for an empty series without fabricating values' {
        $stats = Get-StatisticsSummary -Values @()
        $stats.Count | Should -Be 0
        $stats.Mean | Should -BeNullOrEmpty
    }

    It 'computes mean/min/max correctly' {
        $stats = Get-StatisticsSummary -Values @(10, 20, 30)
        $stats.Mean | Should -Be 20
        $stats.Min | Should -Be 10
        $stats.Max | Should -Be 30
        $stats.Count | Should -Be 3
    }
}

Describe 'Get-HttpStatusClass' {
    It 'classifies 200 as 2xx' { Get-HttpStatusClass -StatusCode 200 | Should -Be '2xx' }
    It 'classifies 302 as 3xx' { Get-HttpStatusClass -StatusCode 302 | Should -Be '3xx' }
    It 'classifies 404 as 4xx' { Get-HttpStatusClass -StatusCode 404 | Should -Be '4xx' }
    It 'classifies 500 as 5xx' { Get-HttpStatusClass -StatusCode 500 | Should -Be '5xx' }
    It 'classifies 100 as Other' { Get-HttpStatusClass -StatusCode 100 | Should -Be 'Other' }
}

Describe 'Get-ResponseStatusBreakdown' {
    It 'computes counts and percentages by class' {
        $records = @(
            [pscustomobject]@{ StatusCode = 200; SubStatus = 0 },
            [pscustomobject]@{ StatusCode = 200; SubStatus = 0 },
            [pscustomobject]@{ StatusCode = 404; SubStatus = 0 },
            [pscustomobject]@{ StatusCode = 500; SubStatus = 19 }
        )
        $breakdown = Get-ResponseStatusBreakdown -Records $records
        $breakdown.Total | Should -Be 4
        ($breakdown.ByClass | Where-Object { $_.Class -eq '2xx' }).Count | Should -Be 2
        ($breakdown.ByClass | Where-Object { $_.Class -eq '4xx' }).Count | Should -Be 1
        ($breakdown.ByClass | Where-Object { $_.Class -eq '5xx' }).Count | Should -Be 1
    }

    It 'reports the exact status.substatus combination' {
        $records = @([pscustomobject]@{ StatusCode = 401; SubStatus = 2 })
        $breakdown = Get-ResponseStatusBreakdown -Records $records
        $breakdown.TopCombos[0].StatusCombo | Should -Be '401.2'
    }
}

Describe 'Get-RequestVolumeByPeriod' {
    It 'buckets requests by hour' {
        $records = @(
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-19T08:05:00Z') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-19T08:45:00Z') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-19T09:10:00Z') }
        )
        $periods = @(Get-RequestVolumeByPeriod -Records $records -Granularity 'Hour')
        $periods.Count | Should -Be 2
        ($periods | Where-Object { $_.Period -eq '2026-08-19T08:00:00' }).RequestCount | Should -Be 2
    }

    It 'buckets requests by day' {
        $records = @(
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-19T08:05:00Z') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-19T23:45:00Z') },
            [pscustomobject]@{ Timestamp = (Get-Date '2026-08-20T00:10:00Z') }
        )
        $periods = @(Get-RequestVolumeByPeriod -Records $records -Granularity 'Day')
        $periods.Count | Should -Be 2
    }

    It 'ignores records without a timestamp rather than throwing' {
        $records = @([pscustomobject]@{ Timestamp = $null })
        { Get-RequestVolumeByPeriod -Records $records -Granularity 'Hour' } | Should -Not -Throw
    }
}

Describe 'Group-RequestsByEndpoint' {
    It 'aggregates request count and latency percentiles per endpoint, ignoring the query string' {
        $records = @(
            [pscustomobject]@{ UriStem = '/ManageSoftDL/policy.xml'; TimeTakenMs = 100; BytesReceived = 10; BytesSent = 200 },
            [pscustomobject]@{ UriStem = '/ManageSoftDL/policy.xml'; TimeTakenMs = 200; BytesReceived = 10; BytesSent = 200 },
            [pscustomobject]@{ UriStem = '/ManageSoftRL/upload.aspx'; TimeTakenMs = 50; BytesReceived = 500; BytesSent = 20 }
        )
        $grouped = @(Group-RequestsByEndpoint -Records $records)
        ($grouped | Where-Object { $_.UriStem -eq '/ManageSoftDL/policy.xml' }).RequestCount | Should -Be 2
        ($grouped | Where-Object { $_.UriStem -eq '/ManageSoftRL/upload.aspx' }).RequestCount | Should -Be 1
    }
}
