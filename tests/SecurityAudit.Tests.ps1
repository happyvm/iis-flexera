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
