BeforeAll {
    . "$PSScriptRoot/../src/Statistics.ps1"
    . "$PSScriptRoot/../src/Reporting.ps1"
}

Describe 'New-CollectionReport' {
    It 'produces a markdown file with the required top-level sections' {
        $summary = [pscustomobject]@{
            Metadata               = $null
            RequestCount           = 10
            LatencyStats           = Get-StatisticsSummary -Values @(10, 20, 30)
            CpuStats               = Get-StatisticsSummary -Values @(5, 10, 15)
            PrivateBytesStats      = Get-StatisticsSummary -Values @(1000, 2000)
            QueueStats             = Get-StatisticsSummary -Values @(0, 0, 1)
            ConnectionStats        = Get-StatisticsSummary -Values @(1, 2, 3)
            RejectedRequestsTotal  = 0
            StatusBreakdown        = [pscustomobject]@{ Total = 10; ByClass = @(); TopCombos = @() }
            TopEndpoints           = @()
            AppPoolRecycleCount    = 0
            Warnings               = @('example warning')
            SecurityControls       = @()
        }

        $outFile = Join-Path ([System.IO.Path]::GetTempPath()) ("report-{0}.md" -f ([guid]::NewGuid()))
        try {
            New-CollectionReport -Summary $summary -Path $outFile
            $content = Get-Content -LiteralPath $outFile -Raw

            $content | Should -Match '# Flexera Beacon IIS Observation Report'
            $content | Should -Match '## 1. Executive summary'
            $content | Should -Match '## 11. Capacity observations'
            $content | Should -Match '## 12. Collection limitations/warnings'
            $content | Should -Match '## 13. Security configuration assessment'
            $content | Should -Match 'example warning'
        }
        finally {
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'never states an invented CPU/latency threshold in the capacity section' {
        $summary = [pscustomobject]@{
            Metadata = $null; RequestCount = 0
            LatencyStats = Get-StatisticsSummary -Values @()
            CpuStats = Get-StatisticsSummary -Values @()
            PrivateBytesStats = Get-StatisticsSummary -Values @()
            QueueStats = Get-StatisticsSummary -Values @()
            ConnectionStats = Get-StatisticsSummary -Values @()
            RejectedRequestsTotal = $null
            StatusBreakdown = [pscustomobject]@{ Total = 0; ByClass = @(); TopCombos = @() }
            TopEndpoints = @(); AppPoolRecycleCount = 0; Warnings = @(); SecurityControls = @()
        }

        $outFile = Join-Path ([System.IO.Path]::GetTempPath()) ("report-{0}.md" -f ([guid]::NewGuid()))
        try {
            New-CollectionReport -Summary $summary -Path $outFile
            $content = Get-Content -LiteralPath $outFile -Raw
            $content | Should -Match 'does not publish universal'
        }
        finally {
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
    }
}
