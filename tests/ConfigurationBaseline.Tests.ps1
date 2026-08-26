BeforeAll {
    . "$PSScriptRoot/../src/ConfigurationBaseline.ps1"
}

Describe 'Get-BeaconTopologyType' {
    It 'reports Standalone when ManageSoftRL and ManageSoftDL share a physical path' {
        Get-BeaconTopologyType -RLPhysicalPath 'C:\inetpub\wwwroot\Flexera' -DLPhysicalPath 'C:\inetpub\wwwroot\Flexera' | Should -Be 'Standalone'
    }

    It 'reports Distinct when physical paths differ, without asserting co-installed' {
        Get-BeaconTopologyType -RLPhysicalPath 'C:\inetpub\wwwroot\RL' -DLPhysicalPath 'C:\inetpub\wwwroot\DL' | Should -Be 'Distinct'
    }

    It 'reports Unknown when a physical path could not be resolved' {
        Get-BeaconTopologyType -RLPhysicalPath $null -DLPhysicalPath 'C:\inetpub\wwwroot\DL' | Should -Be 'Unknown'
    }
}

Describe 'Get-AuthenticationConsistencyFinding' {
    It 'is NOT_APPLICABLE when the topology is not confidently standalone' {
        $finding = Get-AuthenticationConsistencyFinding -TopologyType 'Distinct' -RLAuth $null -DLAuth $null
        $finding.Status | Should -Be 'NOT_APPLICABLE'
    }

    It 'is UNKNOWN for a standalone topology when authentication could not be read' {
        $finding = Get-AuthenticationConsistencyFinding -TopologyType 'Standalone' -RLAuth $null -DLAuth $null
        $finding.Status | Should -Be 'UNKNOWN'
    }

    It 'passes when standalone authentication matches' {
        $auth = [pscustomobject]@{ AnonymousEnabled = $true; BasicEnabled = $false; WindowsEnabled = $false }
        $finding = Get-AuthenticationConsistencyFinding -TopologyType 'Standalone' -RLAuth $auth -DLAuth $auth
        $finding.Status | Should -Be 'PASS'
    }

    It 'fails when standalone authentication is inconsistent, citing the Flexera HTTP 409 behavior' {
        $rl = [pscustomobject]@{ AnonymousEnabled = $false; BasicEnabled = $true; WindowsEnabled = $false }
        $dl = [pscustomobject]@{ AnonymousEnabled = $true; BasicEnabled = $false; WindowsEnabled = $false }
        $finding = Get-AuthenticationConsistencyFinding -TopologyType 'Standalone' -RLAuth $rl -DLAuth $dl
        $finding.Status | Should -Be 'FAIL'
        $finding.EffectiveRecommendation | Should -Match '409'
    }
}

Describe 'Test-RequiredW3CFieldsPresent' {
    It 'reports all fields present when every required field is enabled' {
        $fields = @('date', 'time', 's-sitename', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 'sc-status', 'sc-substatus', 'sc-win32-status', 'cs-bytes', 'sc-bytes', 'time-taken')
        $result = Test-RequiredW3CFieldsPresent -EnabledFields $fields
        $result.AllRequiredFieldsPresent | Should -Be $true
        $result.MissingFields.Count | Should -Be 0
    }

    It 'explains the impact of a missing time-taken field' {
        $result = Test-RequiredW3CFieldsPresent -EnabledFields @('date', 'time', 'cs-uri-stem')
        $result.AllRequiredFieldsPresent | Should -Be $false
        $missing = $result.MissingFields | Where-Object { $_.Field -eq 'time-taken' }
        $missing.Impact | Should -Match 'latency percentiles'
    }

    It 'handles logging that is completely disabled (no fields enabled)' {
        $result = Test-RequiredW3CFieldsPresent -EnabledFields @()
        $result.AllRequiredFieldsPresent | Should -Be $false
        $result.MissingFields.Count | Should -Be 11
    }
}
