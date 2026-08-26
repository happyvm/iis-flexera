# AppPool -> w3wp.exe worker-process mapping and lifecycle tracking.
#
# A PID is not stable for the duration of a multi-day run: IIS can recycle
# a pool and replace the process, and an overlapped recycle can leave two
# worker processes alive for the same pool at once. Callers must refresh
# this mapping every sampling tick rather than caching a PID once
# (SPECIFICATION.md sections 6.2-6.3).

function ConvertFrom-AppCmdListWps {
    <#
        Parses the text output of `appcmd.exe list wps`, e.g.:
            WP "3577" (apppool:Flexera Beacon)
        Unrecognized lines (errors, blank lines) are ignored rather than
        throwing, since this is a fragile text format by nature.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines
    )

    $results = New-Object System.Collections.Generic.List[psobject]

    foreach ($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -match '^WP\s+"(?<pid>\d+)"\s+\(apppool:(?<pool>[^)]+)\)') {
            $results.Add([pscustomobject]@{
                PID         = [int]$Matches['pid']
                AppPoolName = $Matches['pool']
            }) | Out-Null
        }
    }

    return $results
}

function Get-WorkerProcessMap {
    <#
        Live PID <-> AppPool mapping via appcmd.exe. Prefer a structured
        API where practical; this text-parsing path exists because appcmd
        is guaranteed to be present on every supported Windows Server.
    #>
    [CmdletBinding()]
    param(
        [string]$AppCmdPath = (Join-Path $env:windir 'System32/inetsrv/appcmd.exe')
    )

    if (-not (Test-Path -LiteralPath $AppCmdPath)) {
        throw "appcmd.exe not found at $AppCmdPath"
    }

    $output = @(& $AppCmdPath list wps)
    return ConvertFrom-AppCmdListWps -Lines $output
}

function Update-WorkerProcessTracking {
    <#
        Diffs the current worker-process map against the previous sample
        and emits AppPool lifecycle events (WorkerStarted/WorkerStopped/
        OverlappedRecycle). Zero, one or multiple PIDs per pool are all
        valid at any given sample - multiple PIDs is not treated as an
        error (SPECIFICATION.md section 11).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AppPoolNames,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CurrentMap,
        [AllowEmptyCollection()][object[]]$PreviousMap = @()
    )

    $events = New-Object System.Collections.Generic.List[psobject]
    $now = (Get-Date).ToUniversalTime()

    foreach ($poolName in $AppPoolNames) {
        $currentPids  = @($CurrentMap  | Where-Object { $_.AppPoolName -eq $poolName } | Select-Object -ExpandProperty PID)
        $previousPids = @($PreviousMap | Where-Object { $_.AppPoolName -eq $poolName } | Select-Object -ExpandProperty PID)

        $started = @($currentPids  | Where-Object { $_ -notin $previousPids })
        $stopped = @($previousPids | Where-Object { $_ -notin $currentPids })

        foreach ($p in $started) {
            $events.Add([pscustomobject]@{
                Timestamp   = $now
                AppPoolName = $poolName
                EventType   = 'WorkerStarted'
                PID         = $p
                PreviousPID = $null
                Details     = $null
            }) | Out-Null
        }

        foreach ($p in $stopped) {
            $events.Add([pscustomobject]@{
                Timestamp   = $now
                AppPoolName = $poolName
                EventType   = 'WorkerStopped'
                PID         = $null
                PreviousPID = $p
                Details     = $null
            }) | Out-Null
        }

        if ($currentPids.Count -gt 1 -and $previousPids.Count -ge 1) {
            $events.Add([pscustomobject]@{
                Timestamp   = $now
                AppPoolName = $poolName
                EventType   = 'OverlappedRecycle'
                PID         = ($currentPids -join ',')
                PreviousPID = ($previousPids -join ',')
                Details     = "Multiple worker processes observed simultaneously for pool '$poolName'."
            }) | Out-Null
        }
    }

    return $events
}

function Get-ProcessSamples {
    <#
        PID-safe process metrics via the formatted-data WMI/CIM class,
        keyed by IDProcess rather than the "w3wp#1"-style instance name
        (whose numeric suffix can be reassigned after process churn).
        SPECIFICATION.md section 8.3.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$ProcessId
    )

    $uniqueProcessIds = @($ProcessId | Select-Object -Unique)
    if ($uniqueProcessIds.Count -eq 0) { return }

    $filter = ($uniqueProcessIds | ForEach-Object { "IDProcess = $_" }) -join ' OR '
    $processes = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -Filter $filter -ErrorAction SilentlyContinue)
    $processDetails = @(Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction SilentlyContinue)
    $detailsByPid = @{}
    foreach ($detail in $processDetails) { $detailsByPid[[int]$detail.ProcessId] = $detail }

    foreach ($proc in $processes) {
        $detail = $detailsByPid[[int]$proc.IDProcess]
        $startTimeUtc = $null
        if ($detail -and $detail.CreationDate) {
            $startTimeUtc = ConvertTo-UtcDateTime -Value $detail.CreationDate
        }
        $cpuTotalSeconds = $null
        if ($detail -and $null -ne $detail.KernelModeTime -and $null -ne $detail.UserModeTime) {
            $cpuTotalSeconds = [math]::Round(([double]$detail.KernelModeTime + [double]$detail.UserModeTime) / 10000000, 3)
        }
        [pscustomobject]@{
            PID             = [int]$proc.IDProcess
            CPUPercent      = $proc.PercentProcessorTime
            WorkingSetBytes = $proc.WorkingSet
            PrivateBytes    = $proc.PrivateBytes
            ThreadCount     = $proc.ThreadCount
            HandleCount     = $proc.HandleCount
            VirtualBytes    = $proc.VirtualBytes
            UptimeSeconds   = $proc.ElapsedTime
            StartTimeUtc    = $startTimeUtc
            CpuTotalSeconds = $cpuTotalSeconds
        }
    }
}

function Get-ProcessSample {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ProcessId)

    return @(Get-ProcessSamples -ProcessId @($ProcessId))[0]
}

function Get-NormalizedCpuPercent {
    <#
        Win32_PerfFormattedData_PerfProc_Process.PercentProcessorTime is
        scaled to a single logical processor (can exceed 100 on a
        multi-core box). This normalizes to 0-100% of total machine CPU
        capacity for human-readable reporting, per SPECIFICATION.md
        section 8.4, while the raw value is preserved separately.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][double]$RawPercentProcessorTime,
        [int]$LogicalProcessorCount = [Environment]::ProcessorCount
    )

    if ($LogicalProcessorCount -le 0) { return $RawPercentProcessorTime }
    return [math]::Round($RawPercentProcessorTime / $LogicalProcessorCount, 2)
}
