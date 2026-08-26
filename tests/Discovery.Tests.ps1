BeforeAll {
    . "$PSScriptRoot/../src/Discovery.ps1"
}

Describe 'Test-IisDriveAvailable' {
    It 'returns a boolean without throwing, even where no IIS: drive exists' {
        { Test-IisDriveAvailable } | Should -Not -Throw
        Test-IisDriveAvailable | Should -BeOfType [bool]
    }
}

<#
    The rest of Discovery.ps1 (Import-WebAdministrationModule,
    Get-IisFlexeraEndpoints, Get-IisSiteInfo, Get-SslCertificateInfo,
    Get-IisAppPoolInfo, Invoke-FlexeraIisDiscovery) requires a live
    Windows Server with IIS and the WebAdministration module/IIS:\ drive
    (SPECIFICATION.md section 19.2 - integration tests, not unit tests).
    It is syntax-checked in CI but not exercised here.
#>
