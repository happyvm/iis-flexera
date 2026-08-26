Set-StrictMode -Version Latest

# IIS/HTTP.sys performance-counter collection.
#
# Counter names vary slightly across Windows/IIS versions, so every
# counter path is probed for availability before it is requested; a
# missing optional counter must not abort collection
# (SPECIFICATION.md sections 7.3 and 8.1).

function Test-CounterPathExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    try {
        $null = Get-Counter -Counter $Path -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-AvailableWebServiceCounters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteCounterInstance
    )

    $candidates = @(
        'Current Connections',
        'Connection Attempts/sec',
        'Bytes Received/sec',
        'Bytes Sent/sec',
        'Bytes Total/sec',
        'Get Requests/sec',
        'Post Requests/sec',
        'Total Method Requests/sec'
    )

    $available = New-Object System.Collections.Generic.List[string]
    foreach ($c in $candidates) {
        $path = "\Web Service($SiteCounterInstance)\$c"
        if (Test-CounterPathExists -Path $path) { $available.Add($path) | Out-Null }
    }

    return $available
}

function Get-WebServiceSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteCounterInstance
    )

    $paths = @(Get-AvailableWebServiceCounters -SiteCounterInstance $SiteCounterInstance)
    if ($paths.Count -eq 0) { return $null }

    try {
        $sample = Get-Counter -Counter $paths -ErrorAction Stop
    } catch {
        return $null
    }

    $values = @{}
    foreach ($cs in $sample.CounterSamples) {
        $name = ($cs.Path -split '\\')[-1]
        $values[$name] = $cs.CookedValue
    }

    [pscustomobject]@{
        Timestamp                 = Get-Date
        CurrentConnections        = $values['Current Connections']
        ConnectionAttemptsPerSec  = $values['Connection Attempts/sec']
        BytesReceivedPerSec       = $values['Bytes Received/sec']
        BytesSentPerSec           = $values['Bytes Sent/sec']
        BytesTotalPerSec          = $values['Bytes Total/sec']
        GetRequestsPerSec         = $values['Get Requests/sec']
        PostRequestsPerSec        = $values['Post Requests/sec']
        TotalMethodRequestsPerSec = $values['Total Method Requests/sec']
    }
}

function Get-HttpSysQueueSample {
    <#
        CurrentQueueSize = 0 is a valid, usually-healthy reading, not a
        missing value (SPECIFICATION.md section 8.2).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$QueueInstance
    )

    $candidates = @('CurrentQueueSize', 'RejectedRequests', 'ArrivalRate')
    $paths = New-Object System.Collections.Generic.List[string]

    foreach ($c in $candidates) {
        $path = "\HTTP Service Request Queues($QueueInstance)\$c"
        if (Test-CounterPathExists -Path $path) { $paths.Add($path) | Out-Null }
    }

    if ($paths.Count -eq 0) { return $null }

    try {
        $sample = Get-Counter -Counter $paths -ErrorAction Stop
    } catch {
        return $null
    }

    $values = @{}
    foreach ($cs in $sample.CounterSamples) {
        $name = ($cs.Path -split '\\')[-1]
        $values[$name] = $cs.CookedValue
    }

    [pscustomobject]@{
        Timestamp        = Get-Date
        QueueInstance    = $QueueInstance
        CurrentQueueSize = $values['CurrentQueueSize']
        RejectedRequests = $values['RejectedRequests']
        ArrivalRate      = $values['ArrivalRate']
    }
}

function Get-WorkerProcessCounterSample {
    <#
        Depends on Get-ProcessSample / Get-NormalizedCpuPercent from
        src/WorkerProcess.ps1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ProcessId
    )

    $raw = Get-ProcessSample -ProcessId $ProcessId
    if (-not $raw) { return $null }

    [pscustomobject]@{
        Timestamp       = Get-Date
        PID             = $raw.PID
        CPUPercent      = Get-NormalizedCpuPercent -RawPercentProcessorTime $raw.CPUPercent
        RawCPUPercent   = $raw.CPUPercent
        WorkingSetBytes = $raw.WorkingSetBytes
        PrivateBytes    = $raw.PrivateBytes
        ThreadCount     = $raw.ThreadCount
        HandleCount     = $raw.HandleCount
    }
}
