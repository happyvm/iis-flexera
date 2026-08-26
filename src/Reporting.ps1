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

    [void]$sb.AppendLine('# Flexera Beacon IIS Observation Report')
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 1. Executive summary')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Total requests observed: $($Summary.RequestCount)")
    [void]$sb.AppendLine("Application-pool recycle events: $($Summary.AppPoolRecycleCount)")
    [void]$sb.AppendLine("Rejected requests (HTTP.sys): $(Format-OptionalValue -Value $Summary.RejectedRequestsTotal)")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 2. Observation period and collection quality')
    [void]$sb.AppendLine()
    if ($Summary.DateFilter) {
        [void]$sb.AppendLine("Filtered to a single day: $($Summary.DateFilter) (local time)")
    }
    if ($Summary.Metadata) {
        [void]$sb.AppendLine("Start: $($Summary.Metadata.collectionStart)")
        [void]$sb.AppendLine("End: $($Summary.Metadata.collectionEnd)")
        [void]$sb.AppendLine("Sample interval: $($Summary.Metadata.sampleIntervalSeconds)s")
    }
    if ($Summary.Warnings -and @($Summary.Warnings).Count -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Warnings:')
        foreach ($w in $Summary.Warnings) { [void]$sb.AppendLine("- $w") }
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 3. Discovered IIS/Flexera topology')
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

    [void]$sb.AppendLine('## 4. HTTP traffic profile')
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

    [void]$sb.AppendLine('## 5. Response-time profile')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine((Format-StatLine -Stats $Summary.LatencyStats -Unit 'ms'))
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 6. HTTP error profile')
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

    [void]$sb.AppendLine('## 7. IIS worker-process CPU and memory profile')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("CPU (normalized %): $(Format-StatLine -Stats $Summary.CpuStats -Unit '%')")
    [void]$sb.AppendLine("Private Bytes: $(Format-StatLine -Stats $Summary.PrivateBytesStats -Unit ' bytes')")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 8. HTTP.sys queue behavior')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Queue size: $(Format-StatLine -Stats $Summary.QueueStats)")
    [void]$sb.AppendLine("Rejected requests total: $(Format-OptionalValue -Value $Summary.RejectedRequestsTotal)")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 9. Application-pool lifecycle events')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Recycle events observed: $($Summary.AppPoolRecycleCount)")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 10. Top endpoints')
    [void]$sb.AppendLine()
    if ($Summary.TopEndpoints -and @($Summary.TopEndpoints).Count -gt 0) {
        [void]$sb.AppendLine('| Endpoint | Requests | Bytes received | Bytes sent | P95 latency (ms) |')
        [void]$sb.AppendLine('|---|---:|---:|---:|---:|')
        foreach ($ep in $Summary.TopEndpoints) {
            [void]$sb.AppendLine("| $($ep.UriStem) | $($ep.RequestCount) | $($ep.BytesReceived) | $($ep.BytesSent) | $($ep.LatencyP95) |")
        }
    } else {
        [void]$sb.AppendLine('_No endpoint data available._')
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 11. Capacity observations')
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

    [void]$sb.AppendLine('## 12. Collection limitations/warnings')
    [void]$sb.AppendLine()
    if ($Summary.Warnings -and @($Summary.Warnings).Count -gt 0) {
        foreach ($w in $Summary.Warnings) { [void]$sb.AppendLine("- $w") }
    } else {
        [void]$sb.AppendLine('No collection warnings were recorded.')
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 13. Security configuration assessment')
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
        [void]$sb.AppendLine('This is a v0.1 partial control set. See SECURITY-AUDIT.md for the full control catalogue and status model; not every documented control is implemented yet.')
    } else {
        [void]$sb.AppendLine('No security-audit data was available for this run.')
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## 14. Flexera prerequisites & configuration baseline')
    [void]$sb.AppendLine()
    $baseline = $Summary.ConfigurationBaseline
    if ($baseline) {
        [void]$sb.AppendLine("Captured at: $($baseline.CapturedAt)")
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

    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}
