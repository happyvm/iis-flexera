# Markdown report generation.
#
# Capacity wording must stay observational (SPECIFICATION.md section
# 14.2): report measured P50/P95/P99/max evidence, never an invented
# universal threshold.

function Format-StatLine {
    [CmdletBinding()]
    param(
        [object]$Stats,
        [string]$Unit = ''
    )

    if (-not $Stats -or $Stats.Count -eq 0) { return '_No samples available._' }

    "P50: $($Stats.P50)$Unit, P90: $($Stats.P90)$Unit, P95: $($Stats.P95)$Unit, P99: $($Stats.P99)$Unit, Max: $($Stats.Max)$Unit (n=$($Stats.Count))"
}

function Format-OptionalValue {
    <#
        Renders "Unknown" for $null instead of an empty string, so a
        missing data point (e.g. no counters collected for this run)
        reads as explicitly unavailable rather than as a blank that
        looks like a rendering bug.
    #>
    [CmdletBinding()]
    param(
        [object]$Value
    )

    if ($null -eq $Value) { return 'Unknown' }
    return "$Value"
}

function ConvertFrom-PSCustomObjectMap {
    <#
        Yields Key/Value pairs from either a hashtable or a PSCustomObject
        (the shape a hashtable takes after a ConvertTo-Json/ConvertFrom-Json
        round trip), so report rendering works the same whether Baseline
        data came straight from the collector or was reloaded from disk.
    #>
    [CmdletBinding()]
    param(
        [object]$Object
    )

    if (-not $Object) { return @() }

    if ($Object -is [System.Collections.IDictionary]) {
        return @($Object.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Value = $_.Value } })
    }

    return @($Object.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Key = $_.Name; Value = $_.Value } })
}

function New-CollectionReport {
    <#
        Renders the Summary object produced by Analyze-FlexeraBeaconIIS.ps1
        into the Markdown sections required by SPECIFICATION.md section 14
        plus a security section per SECURITY-AUDIT.md section 13.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Path
    )

    $sb = New-Object System.Text.StringBuilder
    $displayLocalTimeZone = [TimeZoneInfo]::Local
    $timestampDisplay = if ($Summary.DisplayTimeZone) { "$($Summary.DisplayTimeZone)" } else { 'UTC' }
    if ($Summary.ReportTimeZone) {
        try { $displayLocalTimeZone = [TimeZoneInfo]::FindSystemTimeZoneById("$($Summary.ReportTimeZone)") } catch { }
    }

    [void]$sb.AppendLine('# Flexera Beacon IIS Observation Report')
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 1. Executive summary')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Total requests observed: $($Summary.RequestCount)")
    [void]$sb.AppendLine("Application-pool recycle events: $($Summary.AppPoolRecycleCount)")
    [void]$sb.AppendLine("Rejected requests (HTTP.sys): $(Format-OptionalValue -Value $Summary.RejectedRequestsTotal)")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 2. Data Quality')
    [void]$sb.AppendLine()
    if ($Summary.DataQuality -and @($Summary.DataQuality).Count -gt 0) {
        [void]$sb.AppendLine('| File | State | Detail |')
        [void]$sb.AppendLine('|---|---|---|')
        foreach ($input in $Summary.DataQuality) {
            $detail = if ($input.Error) { $input.Error -replace '\|', '\|' } elseif ($input.Status -eq 'OUTSIDE_PERIOD') { 'Valid records exist, but none are inside the selected UTC window.' } else { '' }
            [void]$sb.AppendLine("| $([IO.Path]::GetFileName($input.Path)) | $($input.Status) | $detail |")
        }
    } else {
        [void]$sb.AppendLine('_Input-file state was not supplied by this analysis._')
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 3. Observation Period')
    [void]$sb.AppendLine()
    if ($Summary.DateFilter) {
        $dateFilterLabel = if ($Summary.DateFilterEnd) { "period $($Summary.DateFilter) to $($Summary.DateFilterEnd)" } else { "calendar day $($Summary.DateFilter)" }
        [void]$sb.AppendLine("Filtered to $dateFilterLabel in timezone '$($Summary.ReportTimeZone)', using converted UTC boundaries.")
    }
    if ($Summary.Metadata) {
        [void]$sb.AppendLine("Start: $(Format-ReportTimestamp -Value $Summary.Metadata.collectionStart -Display $timestampDisplay -LocalTimeZone $displayLocalTimeZone)")
        [void]$sb.AppendLine("End: $(Format-ReportTimestamp -Value $Summary.Metadata.collectionEnd -Display $timestampDisplay -LocalTimeZone $displayLocalTimeZone)")
        [void]$sb.AppendLine("Sample interval: $($Summary.Metadata.sampleIntervalSeconds)s")
    }
    if ($Summary.Warnings -and @($Summary.Warnings).Count -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Warnings:')
        foreach ($w in $Summary.Warnings) { [void]$sb.AppendLine("- $w") }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('### Discovered IIS/Flexera topology')
    [void]$sb.AppendLine()
    if ($Summary.Metadata -and $Summary.Metadata.iis) {
        [void]$sb.AppendLine("IIS version: $($Summary.Metadata.iis.version)")
        foreach ($site in @($Summary.Metadata.iis.sites)) {
            [void]$sb.AppendLine("- Site: $($site.Name) (id $($site.Id))")
        }
        foreach ($pool in @($Summary.Metadata.iis.applicationPools)) {
            [void]$sb.AppendLine("- AppPool: $($pool.Name), state: $($pool.State)")
        }
        foreach ($ep in @($Summary.Metadata.iis.endpoints)) {
            [void]$sb.AppendLine("- Endpoint: $($ep.EndpointName) -> site '$($ep.SiteName)', pool '$($ep.AppPoolName)', path '$($ep.Path)'")
        }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 4. HTTP Overview')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Total requests: $($Summary.RequestCount)")
    [void]$sb.AppendLine()
    if ($Summary.TrafficByPeriod -and @($Summary.TrafficByPeriod).Count -gt 0) {
        [void]$sb.AppendLine("Requests by $($Summary.TrafficGranularity):")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| Period | Requests |')
        [void]$sb.AppendLine('|---|---:|')
        foreach ($p in $Summary.TrafficByPeriod) {
            [void]$sb.AppendLine("| $($p.Period) | $($p.RequestCount) |")
        }
        [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine('## 5. HTTP Errors')
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 6. HTTP 405 Investigation')
    [void]$sb.AppendLine()
    $analysis405 = $Summary.Http405Analysis
    if ($analysis405 -and $analysis405.Count -gt 0) {
        [void]$sb.AppendLine("HTTP 405 responses: $($analysis405.Count) ($($analysis405.PercentageOfAllRequests)% of logged requests). This is observational evidence and should be investigated by method, endpoint, client and handler/request-filtering configuration.")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### By method')
        [void]$sb.AppendLine('| Method | Count | % of 405 | Status details (substatus, Win32) |')
        [void]$sb.AppendLine('|---|---:|---:|---|')
        foreach ($row in $analysis405.ByMethod) { [void]$sb.AppendLine("| $($row.Method) | $($row.Count) | $($row.PercentageOf405) | $($row.SubStatuses) |") }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### By endpoint and method')
        [void]$sb.AppendLine('| Endpoint | Method | Count | % of 405 | Status details |')
        [void]$sb.AppendLine('|---|---|---:|---:|---|')
        foreach ($row in @($analysis405.ByEndpoint | Select-Object -First 50)) { [void]$sb.AppendLine("| $($row.UriStem) | $($row.Method) | $($row.Count) | $($row.PercentageOf405) | $($row.SubStatuses) |") }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### By client, endpoint and method')
        [void]$sb.AppendLine('| Client | Endpoint | Method | Count |')
        [void]$sb.AppendLine('|---|---|---|---:|')
        foreach ($row in @($analysis405.ByClient | Select-Object -First 50)) { [void]$sb.AppendLine("| $($row.ClientIp) | $($row.UriStem) | $($row.Method) | $($row.Count) |") }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### UTC timeline')
        [void]$sb.AppendLine('| Hour (UTC) | Count |')
        [void]$sb.AppendLine('|---|---:|')
        foreach ($row in $analysis405.ByHourUtc) { [void]$sb.AppendLine("| $($row.PeriodUtc) | $($row.Count) |") }
    } else {
        [void]$sb.AppendLine('No HTTP 405 response was observed in the selected log records.')
    }
    [void]$sb.AppendLine()
    if ($Summary.StatusBreakdown) {
        foreach ($cls in @($Summary.StatusBreakdown.ByClass)) {
            [void]$sb.AppendLine("- $($cls.Class): $($cls.Count) ($($cls.Percentage)%)")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Top status/substatus combinations:')
        foreach ($combo in (@($Summary.StatusBreakdown.TopCombos) | Select-Object -First 10)) {
            [void]$sb.AppendLine("- $($combo.StatusCombo): $($combo.Count)")
        }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 7. Flexera Endpoint Analysis')
    [void]$sb.AppendLine()
    if ($Summary.TopEndpoints -and @($Summary.TopEndpoints).Count -gt 0) {
        [void]$sb.AppendLine('| Endpoint | Diagnostic category | Requests | Errors % | Methods | Top clients | Bytes received | Bytes sent | P50 | P90 | P95 | P99 | Max ms |')
        [void]$sb.AppendLine('|---|---|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|')
        foreach ($ep in $Summary.TopEndpoints) {
            [void]$sb.AppendLine("| $($ep.UriStem) | $($ep.FlexeraCategory) | $($ep.RequestCount) | $($ep.ErrorRatePercent) | $($ep.Methods) | $($ep.TopClients) | $($ep.BytesReceived) | $($ep.BytesSent) | $($ep.LatencyP50) | $($ep.LatencyP90) | $($ep.LatencyP95) | $($ep.LatencyP99) | $($ep.LatencyMax) |")
        }
    } else {
        [void]$sb.AppendLine('_No endpoint data available._')
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 8. Response Time Analysis')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine((Format-StatLine -Stats $Summary.LatencyStats -Unit 'ms'))
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 9. Large Transfers / Throughput')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('`time-taken` includes effects beyond IIS processing, including client bandwidth and network transfer. Throughput below is derived evidence, not proof of an IIS bottleneck.')
    $slowTransfers = @($Summary.TransferAnalysis | Where-Object { $null -ne $_.ThroughputBytesPerSecond } | Sort-Object TimeTakenMs -Descending | Select-Object -First 20)
    if ($slowTransfers.Count -gt 0) {
        [void]$sb.AppendLine('| Endpoint | Method | Status | Time ms | Bytes sent | Bytes/s | Client |')
        [void]$sb.AppendLine('|---|---|---:|---:|---:|---:|---|')
        foreach ($row in $slowTransfers) { [void]$sb.AppendLine("| $($row.UriStem) | $($row.Method) | $($row.StatusCode) | $($row.TimeTakenMs) | $($row.BytesSent) | $($row.ThroughputBytesPerSecond) | $($row.ClientIp) |") }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 10. IIS Application Pool')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('See the effective configuration baseline below. A value differing from an IIS default is custom, not automatically defective.')
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 11. Worker Processes')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("CPU (normalized %): $(Format-StatLine -Stats $Summary.CpuStats -Unit '%')")
    [void]$sb.AppendLine("Private Bytes: $(Format-StatLine -Stats $Summary.PrivateBytesStats -Unit ' bytes')")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 12. IIS Request Queue')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Queue size: $(Format-StatLine -Stats $Summary.QueueStats)")
    [void]$sb.AppendLine("Rejected requests total: $(Format-OptionalValue -Value $Summary.RejectedRequestsTotal)")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 13. Recycles / WAS Events')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Recycle events observed: $($Summary.AppPoolRecycleCount)")
    [void]$sb.AppendLine()
    if ($Summary.CorrelationTimeline -and @($Summary.CorrelationTimeline).Count -gt 0) {
        [void]$sb.AppendLine('Minute-level UTC correlation (temporal co-occurrence, not proof that a specific worker served a request):')
        [void]$sb.AppendLine('| Minute UTC | Requests | 405 | Latency P95/max ms | Worker CPU max % | Private bytes max | Queue max | Worker events |')
        [void]$sb.AppendLine('|---|---:|---:|---|---:|---:|---:|---|')
        foreach ($row in $Summary.CorrelationTimeline) {
            [void]$sb.AppendLine("| $($row.PeriodUtc) | $($row.RequestCount) | $($row.Http405Count) | $($row.LatencyP95Ms)/$($row.LatencyMaxMs) | $($row.WorkerCpuMaxPercent) | $($row.WorkerPrivateBytesMax) | $($row.QueueSizeMax) | $($row.AppPoolEvents) |")
        }
        [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine('## 14. Configuration Baseline')
    [void]$sb.AppendLine()
    $baseline = $Summary.ConfigurationBaseline
    if ($baseline) {
        [void]$sb.AppendLine("Captured at: $($baseline.CapturedAt)")
        [void]$sb.AppendLine()

        [void]$sb.AppendLine('### Application Pools')
        [void]$sb.AppendLine()
        $pools = @($baseline.AppPools)
        if ($pools.Count -gt 0) {
            [void]$sb.AppendLine('| Pool | State | Runtime / pipeline | Queue | Workers | Identity | Idle timeout | Recycling time | Rapid fail | CPU limit/action |')
            [void]$sb.AppendLine('|---|---|---|---:|---:|---|---|---|---|---|')
            foreach ($pool in $pools) {
                [void]$sb.AppendLine("| $($pool.Name) | $($pool.State) | $($pool.ManagedRuntimeVersion) / $($pool.ManagedPipelineMode) | $($pool.QueueLength) | $($pool.ProcessModel.MaxProcesses) | $($pool.ProcessModel.IdentityType) | $($pool.ProcessModel.IdleTimeout) | $($pool.Recycling.PeriodicRestartTime) | $($pool.Failure.RapidFailProtection) | $($pool.Cpu.Limit) / $($pool.Cpu.Action) |")
            }
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('A worker count above 1 indicates Web Garden configuration. It is custom relative to the IIS default, but is not reported as the cause of a problem without correlated evidence or explicit vendor guidance.')
        } else {
            [void]$sb.AppendLine('_Application Pool configuration was not captured for this run._')
        }
        [void]$sb.AppendLine()

        [void]$sb.AppendLine('### IIS role-service prerequisites')
        [void]$sb.AppendLine()
        $roleServices = @(ConvertFrom-PSCustomObjectMap -Object $baseline.Iis.RoleServices)
        if ($roleServices.Count -gt 0) {
            [void]$sb.AppendLine('| Feature | State |')
            [void]$sb.AppendLine('|---|---|')
            foreach ($rs in $roleServices) {
                [void]$sb.AppendLine("| $($rs.Key) | $($rs.Value) |")
            }
        } else {
            [void]$sb.AppendLine('_Not captured for this run._')
        }
        [void]$sb.AppendLine()

        [void]$sb.AppendLine('### Flexera endpoints')
        [void]$sb.AppendLine()
        $endpoints = @($baseline.Endpoints)
        if ($endpoints.Count -gt 0) {
            [void]$sb.AppendLine('| Endpoint | Site | AppPool | WebDAV | Authentication (Anon/Basic/Windows) |')
            [void]$sb.AppendLine('|---|---|---|---|---|')
            foreach ($ep in $endpoints) {
                $auth = if ($ep.Authentication) { "$($ep.Authentication.AnonymousEnabled)/$($ep.Authentication.BasicEnabled)/$($ep.Authentication.WindowsEnabled)" } else { 'Unknown' }
                [void]$sb.AppendLine("| $($ep.Name) | $($ep.Site) | $($ep.AppPool) | $($ep.WebDav) | $auth |")
            }
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('#### HTTP verb filtering and handlers relevant to HTTP 405')
            foreach ($ep in $endpoints) {
                $verbSummary = @($ep.RequestFilteringDetail.Verbs | ForEach-Object { "$($_.Verb):$($_.Allowed)" }) -join ', '
                [void]$sb.AppendLine("- **$($ep.Site)$($ep.Path)**: allow unlisted verbs=$($ep.RequestFilteringDetail.AllowUnlistedVerbs); explicit verbs=$verbSummary; handlers=$(@($ep.Handlers).Count); modules=$(@($ep.Modules).Count).")
            }
        } else {
            [void]$sb.AppendLine('_Not captured for this run._')
        }
        [void]$sb.AppendLine()

        [void]$sb.AppendLine('### W3C logging field completeness')
        [void]$sb.AppendLine()
        $loggingSites = @($baseline.Logging)
        if ($loggingSites.Count -gt 0) {
            foreach ($siteLogging in $loggingSites) {
                [void]$sb.AppendLine("- Site '$($siteLogging.SiteName)': enabled=$($siteLogging.Enabled), format=$($siteLogging.LogFormat)")
                foreach ($missing in @($siteLogging.MissingFields)) {
                    [void]$sb.AppendLine("  - Missing '$($missing.Field)': $($missing.Impact)")
                }
            }
        } else {
            [void]$sb.AppendLine('_Not captured for this run._')
        }
        [void]$sb.AppendLine()

        [void]$sb.AppendLine('### Authentication consistency (ManageSoftRL vs ManageSoftDL)')
        [void]$sb.AppendLine()
        $authFindings = @($baseline.AuthenticationConsistency)
        if ($authFindings.Count -gt 0) {
            foreach ($f in $authFindings) {
                [void]$sb.AppendLine("- $($f.Status): $($f.EffectiveRecommendation)")
            }
        } else {
            [void]$sb.AppendLine('_Not applicable: ManageSoftRL/ManageSoftDL were not both discovered on the same site._')
        }
        [void]$sb.AppendLine()

        if ($baseline.Warnings -and @($baseline.Warnings).Count -gt 0) {
            [void]$sb.AppendLine('### Baseline collection warnings')
            [void]$sb.AppendLine()
            foreach ($w in $baseline.Warnings) { [void]$sb.AppendLine("- $w") }
            [void]$sb.AppendLine()
        }
    } else {
        [void]$sb.AppendLine('No configuration-baseline data was available for this run.')
        [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine('## 15. Security Audit')
    [void]$sb.AppendLine()
    if ($Summary.SecurityControls -and @($Summary.SecurityControls).Count -gt 0) {
        $byStatus = $Summary.SecurityControls | Group-Object -Property Status
        foreach ($g in $byStatus) {
            [void]$sb.AppendLine("- $($g.Name): $($g.Count)")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| Control | Scope | Status | Priority | Effective recommendation |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        foreach ($c in $Summary.SecurityControls) {
            [void]$sb.AppendLine("| $($c.ControlId) | $($c.Scope) | $($c.Status) | $($c.Priority) | $($c.EffectiveRecommendation) |")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('This remains a partial control set. See SECURITY-AUDIT.md for the full control catalogue and status model; not every documented control is implemented yet.')
    } else {
        [void]$sb.AppendLine('No security-audit data was available for this run.')
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 16. Microsoft IIS Comparison')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('Microsoft-backed controls are listed in the Security Audit; consult SECURITY-AUDIT.md for the normative source catalogue because structured source fields are not implemented yet. Custom values are not classified as failures solely because they differ from IIS defaults.')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## 17. Flexera Recommendations')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('Only recommendations carrying explicit Flexera evidence in the Security Audit are presented as Flexera guidance. For other parameters: No Flexera-specific recommendation found.')
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 18. Findings')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('Flexera does not publish universal IIS CPU, memory, request-rate or latency thresholds; the figures below are observed evidence only, not compliance thresholds.')
    [void]$sb.AppendLine()
    if ($Summary.CpuStats -and $Summary.CpuStats.Count -gt 0) {
        [void]$sb.AppendLine("Observed P95 worker CPU was $($Summary.CpuStats.P95)% and maximum was $($Summary.CpuStats.Max)% during the observation window.")
    }
    if ($Summary.QueueStats -and $Summary.QueueStats.Count -gt 0) {
        [void]$sb.AppendLine("Observed maximum HTTP.sys queue depth was $($Summary.QueueStats.Max).")
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 19. Recommended Next Investigations')
    [void]$sb.AppendLine()
    if ($Summary.Warnings -and @($Summary.Warnings).Count -gt 0) {
        foreach ($w in $Summary.Warnings) { [void]$sb.AppendLine("- $w") }
    } else {
        [void]$sb.AppendLine('No collection warnings were recorded.')
    }
    [void]$sb.AppendLine()

    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}
