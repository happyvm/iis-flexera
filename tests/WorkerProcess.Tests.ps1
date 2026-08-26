BeforeAll {
    . "$PSScriptRoot/../src/Time.ps1"
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

Describe 'Get-ProcessSamples' {
    It 'queries the formatted performance provider once for every tracked PID' {
        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_Process') {
                return @(
                    [pscustomobject]@{ ProcessId = 101; CreationDate = '2026-08-26T10:00:00+00:00'; KernelModeTime = 10000000; UserModeTime = 20000000 },
                    [pscustomobject]@{ ProcessId = 202; CreationDate = '2026-08-26T10:01:00+00:00'; KernelModeTime = 20000000; UserModeTime = 30000000 }
                )
            }
            return @(
                [pscustomobject]@{ IDProcess = 101; PercentProcessorTime = 10; WorkingSet = 20; PrivateBytes = 30; ThreadCount = 4; HandleCount = 5; VirtualBytes = 40; ElapsedTime = 50 },
                [pscustomobject]@{ IDProcess = 202; PercentProcessorTime = 11; WorkingSet = 21; PrivateBytes = 31; ThreadCount = 6; HandleCount = 7; VirtualBytes = 41; ElapsedTime = 51 }
            )
        }

        $samples = @(Get-ProcessSamples -ProcessId @(101, 202))

        $samples.Count | Should -Be 2
        $samples.PID | Should -Be @(101, 202)
        Should -Invoke Get-CimInstance -Times 2 -Exactly -ParameterFilter {
            $Filter -eq 'IDProcess = 101 OR IDProcess = 202'
        }
        $samples[0].CpuTotalSeconds | Should -Be 3
    }

    It 'does not query CIM when no worker PID is active' {
        Mock Get-CimInstance { throw 'should not be called' }
        @(Get-ProcessSamples -ProcessId @()).Count | Should -Be 0
        Should -Invoke Get-CimInstance -Times 0 -Exactly
    }
}
