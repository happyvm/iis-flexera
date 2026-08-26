# UTC normalization and report-window helpers.

function ConvertTo-UtcDateTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Value,
        [ValidateSet('Utc', 'Local', 'UnspecifiedAsUtc')][string]$UnspecifiedKind = 'Utc'
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }

    if ($Value -is [datetime]) {
        $dateTime = [datetime]$Value
        if ($dateTime.Kind -eq [DateTimeKind]::Utc) { return $dateTime }
        if ($dateTime.Kind -eq [DateTimeKind]::Local) { return $dateTime.ToUniversalTime() }
        if ($UnspecifiedKind -eq 'Local') {
            return [TimeZoneInfo]::ConvertTimeToUtc($dateTime, [TimeZoneInfo]::Local)
        }
        return [datetime]::SpecifyKind($dateTime, [DateTimeKind]::Utc)
    }

    $text = "$Value"
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    $dto = [datetimeoffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AllowWhiteSpaces
    if ([datetimeoffset]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dto)) {
        # ISO strings without an offset must not silently inherit the analyzer
        # host's timezone. Collector CSV timestamps are expected to carry an
        # offset; W3C values explicitly use UnspecifiedAsUtc.
        $hasOffset = $text -match '(Z|[+-]\d{2}:?\d{2})$'
        if ($hasOffset) { return $dto.UtcDateTime }

        $unspecified = [datetime]::MinValue
        if (-not [datetime]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$unspecified)) { return $null }
        return ConvertTo-UtcDateTime -Value ([datetime]::SpecifyKind($unspecified, [DateTimeKind]::Unspecified)) -UnspecifiedKind $UnspecifiedKind
    }

    return $null
}

function Get-UtcDayRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$Date,
        [Parameter(Mandatory)][TimeZoneInfo]$TimeZone
    )

    $startLocal = [datetime]::SpecifyKind($Date.Date, [DateTimeKind]::Unspecified)
    $endLocal = $startLocal.AddDays(1)
    if ($TimeZone.IsInvalidTime($startLocal) -or $TimeZone.IsInvalidTime($endLocal)) {
        throw "The selected date boundary is invalid in timezone '$($TimeZone.Id)' because of a daylight-saving transition."
    }

    [pscustomobject]@{
        StartUtc = [TimeZoneInfo]::ConvertTimeToUtc($startLocal, $TimeZone)
        EndUtc   = [TimeZoneInfo]::ConvertTimeToUtc($endLocal, $TimeZone)
        TimeZone = $TimeZone.Id
    }
}

function Format-ReportTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Value,
        [ValidateSet('UTC', 'Local', 'Both')][string]$Display = 'UTC',
        [TimeZoneInfo]$LocalTimeZone = [TimeZoneInfo]::Local
    )

    $utc = ConvertTo-UtcDateTime -Value $Value
    if ($null -eq $utc) { return 'Unknown' }
    $utcText = $utc.ToString('yyyy-MM-dd HH:mm:ss ''UTC''', [Globalization.CultureInfo]::InvariantCulture)
    if ($Display -eq 'UTC') { return $utcText }

    $local = [TimeZoneInfo]::ConvertTimeFromUtc($utc, $LocalTimeZone)
    $localText = "$($local.ToString('yyyy-MM-dd HH:mm:ss')) $($LocalTimeZone.Id)"
    if ($Display -eq 'Local') { return $localText }
    return "$utcText / $localText"
}
