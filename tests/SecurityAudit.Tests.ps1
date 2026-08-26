BeforeAll {
    . "$PSScriptRoot/../src/SecurityAudit.ps1"
}

Describe 'Get-HttpsUsageControl' {
    It 'passes when HTTPS is present' {
        (Get-HttpsUsageControl -HttpsBindingPresent $true -HttpBindingPresent $false).Status | Should -Be 'PASS'
    }

    It 'warns when only HTTP is present' {
        (Get-HttpsUsageControl -HttpsBindingPresent $false -HttpBindingPresent $true).Status | Should -Be 'WARNING'
    }

    It 'is unknown when no binding could be resolved' {
        (Get-HttpsUsageControl -HttpsBindingPresent $false -HttpBindingPresent $false).Status | Should -Be 'UNKNOWN'
    }
}

Describe 'Get-StandardPortControl' {
    It 'passes for the documented default HTTPS port' {
        (Get-StandardPortControl -Port 443 -Protocol 'https').Status | Should -Be 'PASS'
    }

    It 'warns for a custom port instead of silently accepting it as equivalent' {
        (Get-StandardPortControl -Port 8443 -Protocol 'https').Status | Should -Be 'WARNING'
    }
}

Describe 'Get-BasicAuthenticationControl' {
    It 'fails Basic Authentication over HTTP' {
        (Get-BasicAuthenticationControl -BasicAuthEnabled $true -HttpsEnforced $false).Status | Should -Be 'FAIL'
    }

    It 'passes Basic Authentication over enforced HTTPS' {
        (Get-BasicAuthenticationControl -BasicAuthEnabled $true -HttpsEnforced $true).Status | Should -Be 'PASS'
    }

    It 'is not applicable when Basic Authentication is disabled' {
        (Get-BasicAuthenticationControl -BasicAuthEnabled $false -HttpsEnforced $false).Status | Should -Be 'NOT_APPLICABLE'
    }
}

Describe 'Get-AnonymousAuthenticationControl' {
    It 'treats anonymous + HTTPS as a documented Flexera exception, not a generic failure' {
        (Get-AnonymousAuthenticationControl -AnonymousEnabled $true -HttpsEnforced $true).Status | Should -Be 'FLEXERA_EXCEPTION'
    }

    It 'warns for anonymous access over plain HTTP' {
        (Get-AnonymousAuthenticationControl -AnonymousEnabled $true -HttpsEnforced $false).Status | Should -Be 'WARNING'
    }
}

Describe 'Get-WebDavControl' {
    It 'fails when WebDAV is enabled' {
        (Get-WebDavControl -WebDavState 'Enabled').Status | Should -Be 'FAIL'
    }

    It 'passes when WebDAV is disabled or not installed' {
        (Get-WebDavControl -WebDavState 'Disabled').Status | Should -Be 'PASS'
        (Get-WebDavControl -WebDavState 'Not installed').Status | Should -Be 'PASS'
    }

    It 'is unknown for an unrecognized state rather than guessing' {
        (Get-WebDavControl -WebDavState 'Unknown').Status | Should -Be 'UNKNOWN'
    }
}

Describe 'Get-RequestFilteringExtensionControl' {
    It 'fails when a Flexera-required extension is blocked' {
        $states = @{ '.osd' = 'Blocked'; '.npl' = 'Allowed'; '.nds' = 'Allowed'; '.ini' = 'Allowed' }
        (Get-RequestFilteringExtensionControl -ExtensionStates $states -RequestFilteringEnabled $true).Status | Should -Be 'FAIL'
    }

    It 'passes when all Flexera extensions are allowed and filtering is enabled' {
        $states = @{ '.osd' = 'Allowed'; '.npl' = 'Allowed'; '.nds' = 'Allowed'; '.ini' = 'Allowed' }
        (Get-RequestFilteringExtensionControl -ExtensionStates $states -RequestFilteringEnabled $true).Status | Should -Be 'PASS'
    }

    It 'warns when filtering is disabled but nothing is blocked' {
        $states = @{ '.osd' = 'NotExplicitlyConfigured' }
        (Get-RequestFilteringExtensionControl -ExtensionStates $states -RequestFilteringEnabled $false).Status | Should -Be 'WARNING'
    }
}

Describe 'Get-AppPoolIdentityControl' {
    It 'passes for ApplicationPoolIdentity' {
        (Get-AppPoolIdentityControl -IdentityType 'ApplicationPoolIdentity').Status | Should -Be 'PASS'
    }

    It 'fails for LocalSystem' {
        (Get-AppPoolIdentityControl -IdentityType 'LocalSystem').Status | Should -Be 'FAIL'
    }
}

Describe 'Get-CertificateCommonName' {
    It 'extracts a plain CN' {
        Get-CertificateCommonName -Subject 'CN=beacon.example.com, O=Example Corp' | Should -Be 'beacon.example.com'
    }

    It 'strips .NET''s quoting around a CN with a trailing space, observed on a real certificate' {
        Get-CertificateCommonName -Subject 'CN="emsw3030.fr1.grs.net ", OU=IT' | Should -Be 'emsw3030.fr1.grs.net'
    }

    It 'returns $null when the Subject has no CN' {
        Get-CertificateCommonName -Subject 'O=Example Corp' | Should -BeNullOrEmpty
    }
}

Describe 'Get-ClientCertificateMode' {
    It 'decodes SslRequireCert as Require' {
        Get-ClientCertificateMode -SslFlags 4 | Should -Be 'Require'
    }

    It 'decodes SslNegotiateCert alone as Accept' {
        Get-ClientCertificateMode -SslFlags 2 | Should -Be 'Accept'
    }

    It 'decodes no client-cert bits as Ignore' {
        Get-ClientCertificateMode -SslFlags 1 | Should -Be 'Ignore'
    }
}

Describe 'Get-CertificateValidityControl' {
    It 'passes for a certificate comfortably within its validity window' {
        $now = Get-Date '2026-06-01'
        $result = Get-CertificateValidityControl -NotBefore (Get-Date '2026-01-01') -NotAfter (Get-Date '2027-01-01') -Now $now
        $result.Status | Should -Be 'PASS'
    }

    It 'warns when the certificate expires within the warning window' {
        $now = Get-Date '2026-06-01'
        $result = Get-CertificateValidityControl -NotBefore (Get-Date '2026-01-01') -NotAfter (Get-Date '2026-06-10') -Now $now -WarningWindowDays 30
        $result.Status | Should -Be 'WARNING'
    }

    It 'fails for an already-expired certificate' {
        $now = Get-Date '2026-06-01'
        $result = Get-CertificateValidityControl -NotBefore (Get-Date '2025-01-01') -NotAfter (Get-Date '2026-01-01') -Now $now
        $result.Status | Should -Be 'FAIL'
    }

    It 'fails for a not-yet-valid certificate' {
        $now = Get-Date '2026-01-01'
        $result = Get-CertificateValidityControl -NotBefore (Get-Date '2026-06-01') -NotAfter (Get-Date '2027-01-01') -Now $now
        $result.Status | Should -Be 'FAIL'
    }
}

Describe 'Get-CertificateNameMatchControl' {
    It 'passes for an exact SAN match' {
        (Get-CertificateNameMatchControl -ExpectedHostName 'beacon.example.com' -CertificateNames @('beacon.example.com')).Status | Should -Be 'PASS'
    }

    It 'passes for a matching wildcard SAN' {
        (Get-CertificateNameMatchControl -ExpectedHostName 'beacon.example.com' -CertificateNames @('*.example.com')).Status | Should -Be 'PASS'
    }

    It 'fails when no certificate name matches the expected host' {
        (Get-CertificateNameMatchControl -ExpectedHostName 'beacon.example.com' -CertificateNames @('other.example.com')).Status | Should -Be 'FAIL'
    }

    It 'is unknown when no certificate names could be read' {
        (Get-CertificateNameMatchControl -ExpectedHostName 'beacon.example.com' -CertificateNames @()).Status | Should -Be 'UNKNOWN'
    }
}

Describe 'Get-MutualTlsControl' {
    It 'is not applicable when client certificates are ignored' {
        (Get-MutualTlsControl -HttpsPresent $true -ClientCertificateMode 'Ignore').Status | Should -Be 'NOT_APPLICABLE'
    }

    It 'is informational for a correctly configured Require mode over HTTPS' {
        (Get-MutualTlsControl -HttpsPresent $true -ClientCertificateMode 'Require').Status | Should -Be 'INFO'
    }

    It 'fails when client certificates are required but HTTPS is not present' {
        (Get-MutualTlsControl -HttpsPresent $false -ClientCertificateMode 'Require').Status | Should -Be 'FAIL'
    }
}

Describe 'Invoke-FlexeraSecurityAudit' {
    It 'wires topology/baseline data into HTTPS, port, AppPool identity, WebDAV, auth and logging controls without throwing' {
        $topology = [pscustomobject]@{
            SelectedSites = @(
                [pscustomobject]@{
                    Name     = 'Default Web Site'
                    Bindings = @(
                        [pscustomobject]@{ Protocol = 'https'; BindingInformation = '*:443:beacon.example.com'; CertificateHash = $null; SslFlags = 0 },
                        [pscustomobject]@{ Protocol = 'http'; BindingInformation = '*:80:beacon.example.com'; CertificateHash = $null; SslFlags = 0 }
                    )
                }
            )
            SelectedAppPools = @(
                [pscustomobject]@{ Name = 'Flexera Beacon'; IdentityType = 'ApplicationPoolIdentity' }
            )
        }

        $baseline = [pscustomobject]@{
            Endpoints = @(
                [pscustomobject]@{
                    Name             = 'ManageSoftRL'
                    Site             = 'Default Web Site'
                    Path             = '/ManageSoftRL'
                    WebDav           = 'Disabled'
                    RequestFiltering = @{ '.osd' = 'Allowed'; '.npl' = 'Allowed'; '.nds' = 'Allowed'; '.ini' = 'Allowed' }
                    Authentication   = [pscustomobject]@{ AnonymousEnabled = $true; BasicEnabled = $false; WindowsEnabled = $false }
                },
                [pscustomobject]@{
                    Name             = 'ManageSoftDL'
                    Site             = 'Default Web Site'
                    Path             = '/ManageSoftDL'
                    WebDav           = 'Disabled'
                    RequestFiltering = @{ '.osd' = 'Allowed'; '.npl' = 'Allowed'; '.nds' = 'Allowed'; '.ini' = 'Allowed' }
                    Authentication   = [pscustomobject]@{ AnonymousEnabled = $true; BasicEnabled = $false; WindowsEnabled = $false }
                }
            )
            Logging = @(
                [pscustomobject]@{ SiteName = 'Default Web Site'; Enabled = $true; EnabledFields = @('date', 'time', 'time-taken') }
            )
            AuthenticationConsistency = @(
                [pscustomobject]@{ ControlId = 'FB-IIS-BASE-001'; Status = 'PASS'; EffectiveRecommendation = 'consistent' }
            )
        }

        $controls = Invoke-FlexeraSecurityAudit -Topology $topology -Baseline $baseline

        $controls.Count | Should -BeGreaterThan 0
        ($controls | Where-Object { $_.ControlId -eq 'FB-IIS-SEC-001' }).Status | Should -Be 'PASS'
        $anonFindings = @($controls | Where-Object { $_.ControlId -eq 'FB-IIS-SEC-007' })
        $anonFindings.Count | Should -Be 2
        $anonFindings | ForEach-Object { $_.Status | Should -Be 'FLEXERA_EXCEPTION' }
        ($controls | Where-Object { $_.ControlId -eq 'FB-IIS-SEC-013' }).Status | Should -Be 'PASS'
        ($controls | Where-Object { $_.ControlId -eq 'FB-IIS-SEC-015' }).Status | Should -Be 'PASS'
        ($controls | Where-Object { $_.ControlId -eq 'FB-IIS-BASE-001' }).Status | Should -Be 'PASS'

        # RL and DL produce identical WebDAV findings by content (same
        # shared config in this fixture), but Scope must still tell them
        # apart rather than looking like an accidental duplicate.
        $webDavFindings = @($controls | Where-Object { $_.ControlId -eq 'FB-IIS-SEC-009' })
        $webDavFindings.Count | Should -Be 2
        @($webDavFindings.Scope | Select-Object -Unique).Count | Should -Be 2
        $webDavFindings.Scope | Should -Contain 'Default Web Site/ManageSoftRL'
        $webDavFindings.Scope | Should -Contain 'Default Web Site/ManageSoftDL'
    }

    It 'returns an empty array without throwing when nothing was discovered' {
        $topology = [pscustomobject]@{ SelectedSites = @(); SelectedAppPools = @() }
        $baseline = [pscustomobject]@{ Endpoints = @(); Logging = @(); AuthenticationConsistency = @() }

        $controls = Invoke-FlexeraSecurityAudit -Topology $topology -Baseline $baseline
        $controls.Count | Should -Be 0
    }
}

Describe 'Get-HttpLoggingControl' {
    It 'fails when logging is disabled' {
        (Get-HttpLoggingControl -LoggingEnabled $false -TimeTakenFieldPresent $false).Status | Should -Be 'FAIL'
    }

    It 'warns when logging is enabled but time-taken is missing' {
        (Get-HttpLoggingControl -LoggingEnabled $true -TimeTakenFieldPresent $false).Status | Should -Be 'WARNING'
    }

    It 'passes when logging is enabled with time-taken present' {
        (Get-HttpLoggingControl -LoggingEnabled $true -TimeTakenFieldPresent $true).Status | Should -Be 'PASS'
    }
}
