BeforeAll {
    . "$PSScriptRoot/../src/Time.ps1"
    . "$PSScriptRoot/../src/WorkerProcess.ps1"
    . "$PSScriptRoot/../src/PerformanceCounters.ps1"
}

BeforeEach {
    $script:WebServiceCounterPathCache = @{}
    $script:HttpSysCounterPathCache = @{}
}

Describe 'performance counter path caching' {
    It 'probes Web Service paths only on the first sample for a site' {
        Mock Get-Counter {
            param($Counter)
            [pscustomobject]@{ CounterSamples = @() }
        }

        Get-WebServiceSample -SiteCounterInstance 'Flexera Site' | Out-Null
        Get-WebServiceSample -SiteCounterInstance 'Flexera Site' | Out-Null

        Should -Invoke Get-Counter -Times 14 -Exactly
        Should -Invoke Get-Counter -Times 2 -Exactly -ParameterFilter { $Counter -is [array] }
    }

    It 'probes HTTP.sys paths only on the first sample for a queue' {
        Mock Get-Counter {
            param($Counter)
            [pscustomobject]@{ CounterSamples = @() }
        }

        Get-HttpSysQueueSample -QueueInstance 'FlexeraPool' | Out-Null
        Get-HttpSysQueueSample -QueueInstance 'FlexeraPool' | Out-Null

        Should -Invoke Get-Counter -Times 8 -Exactly
        Should -Invoke Get-Counter -Times 2 -Exactly -ParameterFilter { $Counter -is [array] }
    }

    It 'continues when optional counters are unavailable and caches that resolution' {
        Mock Get-Counter {
            param($Counter)
            if ($Counter -is [string] -and $Counter -match 'Maximum Connections|CacheHitRate') { throw 'counter unavailable' }
            [pscustomobject]@{ CounterSamples = @() }
        }

        { Get-WebServiceSample -SiteCounterInstance 'Older IIS' } | Should -Not -Throw
        { Get-WebServiceSample -SiteCounterInstance 'Older IIS' } | Should -Not -Throw
        Should -Invoke Get-Counter -Times 14 -Exactly
    }
}

Describe 'Get-IisSiteAppPoolPairs' {
    It 'deduplicates a shared site/pool pair discovered through multiple endpoints' {
        $endpoints = @(
            [pscustomobject]@{ SiteName='Beacon'; AppPoolName='Flexera' },
            [pscustomobject]@{ SiteName='Beacon'; AppPoolName='Flexera' }
        )
        $pairs = @(Get-IisSiteAppPoolPairs -Endpoints $endpoints)
        $pairs.Count | Should -Be 1
        $pairs[0].SiteName | Should -Be 'Beacon'
        $pairs[0].AppPoolName | Should -Be 'Flexera'
    }
}
