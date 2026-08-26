BeforeAll {
    . "$PSScriptRoot/../src/Time.ps1"
}

Describe 'UTC timestamp normalization' {
    It 'keeps UTC timestamps in UTC' {
        (ConvertTo-UtcDateTime '2026-01-15T12:00:00Z').ToString('o') | Should -Match '^2026-01-15T12:00:00'
    }

    It 'normalizes UTC+1 and UTC+2 ISO8601 offsets' {
        (ConvertTo-UtcDateTime '2026-01-15T13:00:00+01:00').Hour | Should -Be 12
        (ConvertTo-UtcDateTime '2026-07-15T14:00:00+02:00').Hour | Should -Be 12
    }

    It 'treats a W3C timestamp without an offset as UTC' {
        $result = ConvertTo-UtcDateTime '2026-08-26 09:30:00' -UnspecifiedKind UnspecifiedAsUtc
        $result.Kind | Should -Be ([DateTimeKind]::Utc)
        $result.Hour | Should -Be 9
    }

    It 'uses real DST boundaries when selecting a Europe/Paris day' {
        $zoneId = if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) { 'Romance Standard Time' } else { 'Europe/Paris' }
        $zone = [TimeZoneInfo]::FindSystemTimeZoneById($zoneId)
        ((Get-UtcDayRange -Date ([datetime]'2026-03-29') -TimeZone $zone).EndUtc - (Get-UtcDayRange -Date ([datetime]'2026-03-29') -TimeZone $zone).StartUtc).TotalHours | Should -Be 23
        ((Get-UtcDayRange -Date ([datetime]'2026-10-25') -TimeZone $zone).EndUtc - (Get-UtcDayRange -Date ([datetime]'2026-10-25') -TimeZone $zone).StartUtc).TotalHours | Should -Be 25
    }
}
