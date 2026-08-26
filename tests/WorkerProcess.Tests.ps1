BeforeAll {
    . "$PSScriptRoot/../src/WorkerProcess.ps1"
}

Describe 'ConvertFrom-AppCmdListWps' {
    It 'parses standard appcmd list wps output' {
        $lines = @(
            'WP "3577" (apppool:Flexera Beacon)',
            'WP "4021" (apppool:DefaultAppPool)'
        )
        $result = @(ConvertFrom-AppCmdListWps -Lines $lines)
        $result.Count | Should -Be 2
        $result[0].PID | Should -Be 3577
        $result[0].AppPoolName | Should -Be 'Flexera Beacon'
    }

    It 'ignores blank lines' {
        $lines = @('WP "100" (apppool:Pool A)', '', '   ')
        $result = @(ConvertFrom-AppCmdListWps -Lines $lines)
        $result.Count | Should -Be 1
    }

    It 'returns no results for unrecognized output' {
        $result = @(ConvertFrom-AppCmdListWps -Lines @('ERROR ( message:Some error )'))
        $result.Count | Should -Be 0
    }
}

Describe 'Update-WorkerProcessTracking' {
    It 'reports a WorkerStarted event for a brand-new PID' {
        $current = @([pscustomobject]@{ PID = 100; AppPoolName = 'Flexera Beacon' })
        $events = @(Update-WorkerProcessTracking -AppPoolNames @('Flexera Beacon') -CurrentMap $current -PreviousMap @())
        $events.Count | Should -Be 1
        $events[0].EventType | Should -Be 'WorkerStarted'
        $events[0].PID | Should -Be 100
    }

    It 'reports WorkerStopped when a PID disappears' {
        $previous = @([pscustomobject]@{ PID = 100; AppPoolName = 'Flexera Beacon' })
        $events = @(Update-WorkerProcessTracking -AppPoolNames @('Flexera Beacon') -CurrentMap @() -PreviousMap $previous)
        $events[0].EventType | Should -Be 'WorkerStopped'
        $events[0].PreviousPID | Should -Be 100
    }

    It 'reports OverlappedRecycle when two PIDs are present at once for the same pool' {
        $previous = @([pscustomobject]@{ PID = 100; AppPoolName = 'Flexera Beacon' })
        $current = @(
            [pscustomobject]@{ PID = 100; AppPoolName = 'Flexera Beacon' },
            [pscustomobject]@{ PID = 200; AppPoolName = 'Flexera Beacon' }
        )
        $events = @(Update-WorkerProcessTracking -AppPoolNames @('Flexera Beacon') -CurrentMap $current -PreviousMap $previous)
        @($events | Where-Object { $_.EventType -eq 'OverlappedRecycle' }).Count | Should -Be 1
    }

    It 'does not error when zero PIDs exist for a pool' {
        { Update-WorkerProcessTracking -AppPoolNames @('Flexera Beacon') -CurrentMap @() -PreviousMap @() } | Should -Not -Throw
    }
}

Describe 'Get-NormalizedCpuPercent' {
    It 'divides raw single-core percentage by the logical processor count' {
        Get-NormalizedCpuPercent -RawPercentProcessorTime 400 -LogicalProcessorCount 4 | Should -Be 100
    }

    It 'returns the raw value unchanged when the processor count is unknown' {
        Get-NormalizedCpuPercent -RawPercentProcessorTime 42 -LogicalProcessorCount 0 | Should -Be 42
    }
}
