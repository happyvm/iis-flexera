# IIS/HTTP.sys performance-counter collection.
#
# Counter names vary slightly across Windows/IIS versions, so every
# counter path is probed for availability before it is requested; a
# missing optional counter must not abort collection
# (SPECIFICATION.md sections 7.3 and 8.1).

# Counter availability is stable during a collector run. Cache the resolved
# paths per instance so subsequent ticks perform only the actual batch read.
$script:WebServiceCounterPathCache = @{}
$script:HttpSysCounterPathCache = @{}

function Get-IisSiteAppPoolPairs {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Endpoints = @(),
        [AllowEmptyCollection()][object[]]$Sites = @(),
        [AllowEmptyCollection()][string[]]$AppPoolNames = @()
    )

    $pairs = @($Endpoints | Where-Object { $_.SiteName -and $_.AppPoolName } |
        Select-Object @{Name='SiteName';Expression={$_.SiteName}}, @{Name='AppPoolName';Expression={$_.AppPoolName}} -Unique)
    if ($pairs.Count -gt 0) { return $pairs }

    foreach ($site in $Sites) {
        foreach ($poolName in $AppPoolNames) { [pscustomobject]@{ SiteName=$site.Name; AppPoolName=$poolName } }
    }
}

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

    if ($script:WebServiceCounterPathCache.ContainsKey($SiteCounterInstance)) {
        return @($script:WebServiceCounterPathCache[$SiteCounterInstance])
    }

    $candidates = @(
        'Current Connections',
        'Connection Attempts/sec',
        'Bytes Received/sec',
        'Bytes Sent/sec',
        'Bytes Total/sec',
        'Get Requests/sec',
        'Post Requests/sec',
        'Total Method Requests/sec',
        'Maximum Connections',
        'Current Anonymous Users',
        'Current Non-Anonymous Users',
        'Service Uptime'
    )

    $available = New-Object System.Collections.Generic.List[string]
    foreach ($c in $candidates) {
        $path = "\Web Service($SiteCounterInstance)\$c"
        if (Test-CounterPathExists -Path $path) { $available.Add($path) | Out-Null }
    }

    $resolved = @($available)
    $script:WebServiceCounterPathCache[$SiteCounterInstance] = $resolved
    return $resolved
}

function Get-AvailableHttpSysQueueCounters {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$QueueInstance)

    if ($script:HttpSysCounterPathCache.ContainsKey($QueueInstance)) {
        return @($script:HttpSysCounterPathCache[$QueueInstance])
    }

    $available = New-Object System.Collections.Generic.List[string]
    foreach ($counterName in @('CurrentQueueSize', 'RejectedRequests', 'ArrivalRate', 'CacheHitRate', 'MaxQueueItemAge', 'ActiveRequests')) {
        $path = "\HTTP Service Request Queues($QueueInstance)\$counterName"
        if (Test-CounterPathExists -Path $path) { $available.Add($path) | Out-Null }
    }

    $resolved = @($available)
    $script:HttpSysCounterPathCache[$QueueInstance] = $resolved
    return $resolved
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
        MaximumConnections        = $values['Maximum Connections']
        CurrentAnonymousUsers     = $values['Current Anonymous Users']
        CurrentNonAnonymousUsers  = $values['Current Non-Anonymous Users']
        ServiceUptimeSeconds      = $values['Service Uptime']
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

    $paths = @(Get-AvailableHttpSysQueueCounters -QueueInstance $QueueInstance)

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
        CacheHitRate     = $values['CacheHitRate']
        MaxQueueItemAge  = $values['MaxQueueItemAge']
        ActiveRequests   = $values['ActiveRequests']
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
        VirtualBytes    = $raw.VirtualBytes
        UptimeSeconds   = $raw.UptimeSeconds
        StartTimeUtc    = $raw.StartTimeUtc
        CpuTotalSeconds = $raw.CpuTotalSeconds
    }
}

function Get-WorkerProcessCounterSamples {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$ProcessId
    )

    foreach ($raw in @(Get-ProcessSamples -ProcessId $ProcessId)) {
        [pscustomobject]@{
            Timestamp       = Get-Date
            PID             = $raw.PID
            CPUPercent      = Get-NormalizedCpuPercent -RawPercentProcessorTime $raw.CPUPercent
            RawCPUPercent   = $raw.CPUPercent
            WorkingSetBytes = $raw.WorkingSetBytes
            PrivateBytes    = $raw.PrivateBytes
            ThreadCount     = $raw.ThreadCount
            HandleCount     = $raw.HandleCount
            VirtualBytes    = $raw.VirtualBytes
            UptimeSeconds   = $raw.UptimeSeconds
            StartTimeUtc    = $raw.StartTimeUtc
            CpuTotalSeconds = $raw.CpuTotalSeconds
        }
    }
}
