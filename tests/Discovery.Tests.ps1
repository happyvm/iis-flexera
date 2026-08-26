BeforeAll {
    . "$PSScriptRoot/../src/Discovery.ps1"
}

Describe 'Import-WebAdministrationModule' {
    It 'returns immediately without attempting to import when the module is already loaded' {
        Mock Get-Module { [pscustomobject]@{ Name = 'WebAdministration' } } -ParameterFilter { $Name -eq 'WebAdministration' }
        Mock Import-Module { throw 'Import-Module should not be called when the module is already loaded' }

        { Import-WebAdministrationModule } | Should -Not -Throw
    }
}

<#
    The rest of Discovery.ps1 (Get-IisFlexeraEndpoints, Get-IisSiteInfo,
    Get-SslCertificateInfo, Get-IisAppPoolInfo, Invoke-FlexeraIisDiscovery,
    and the actual module-loading paths in Import-WebAdministrationModule)
    requires a live Windows Server with IIS and the WebAdministration
    module (SPECIFICATION.md section 19.2 - integration tests, not unit
    tests). -UseWindowsPowerShell's behavior on a genuinely missing module
    also differs across platforms in ways not safely assertable here.
    Syntax-checked in CI but not exercised here.
#>
