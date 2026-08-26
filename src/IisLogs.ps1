# IIS W3C extended log parsing.
#
# Field order in a W3C log is configurable per site, so the parser always
# builds its column list from the "#Fields:" header instead of assuming a
# fixed positional schema (SPECIFICATION.md section 9.3).

function ConvertFrom-W3CFieldsLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Line
    )

    if ($Line -notmatch '^#Fields:\s*(.+)$') {
        throw "Not a #Fields: line: $Line"
    }

    return @($Matches[1] -split '\s+' | Where-Object { $_ -ne '' })
}

function Read-W3CLogFile {
    <#
        Parses a single IIS W3C log file. Comment lines (including
        "#Fields:") are consumed for schema discovery. Data rows whose
        token count does not match the declared field count are counted
        as malformed and skipped rather than aborting the whole file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "IIS log file not found: $Path"
    }

    $fields = $null
    $malformedCount = 0
    $records = New-Object System.Collections.Generic.List[object]

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line.StartsWith('#')) {
            if ($line.StartsWith('#Fields:')) {
                $fields = ConvertFrom-W3CFieldsLine -Line $line
            }
            continue
        }

        if (-not $fields) {
            # A data row appeared before any #Fields: header was seen.
            $malformedCount++
            continue
        }

        $values = $line -split ' '

        if ($values.Count -ne $fields.Count) {
            $malformedCount++
            continue
        }

        $record = [ordered]@{}
        for ($i = 0; $i -lt $fields.Count; $i++) {
            $record[$fields[$i]] = $values[$i]
        }

        $records.Add([pscustomobject]$record) | Out-Null
    }

    [pscustomobject]@{
        Path           = $Path
        Fields         = $fields
        RecordCount    = $records.Count
        MalformedCount = $malformedCount
        Records        = $records
    }
}

function Get-W3CLogFileSet {
    <#
        Expands a mix of file and directory paths into a sorted list of
        concrete *.log files. Observation runs are not guaranteed to fit
        in a single file (log rotation) - SPECIFICATION.md section 9.4.

        -SinceDate is an optional, deliberately one-sided pre-filter for
        directory expansion only (an explicitly named file is always
        included - the caller pointed at it on purpose): it skips a file
        whose LastWriteTime is before that date, since an append-only IIS
        log can never contain entries from that date or later without
        having been written to on or after it. It never skips a file for
        being "too late" (e.g. Weekly/Monthly/Unlimited/MaxSize log
        rotation can leave one file's LastWriteTime long after some of
        its actual content's dates), so it can only reduce work, never
        silently drop data - Select-ByDate on the parsed records remains
        the authoritative filter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Path,
        [datetime]$SinceDate
    )

    $files = New-Object System.Collections.Generic.List[string]

    foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            $candidates = Get-ChildItem -LiteralPath $p -Filter '*.log' -File
            if ($SinceDate) {
                $candidates = $candidates | Where-Object { $_.LastWriteTime -ge $SinceDate.Date }
            }
            $candidates |
                Sort-Object Name |
                ForEach-Object { $files.Add($_.FullName) }
        }
        elseif (Test-Path -LiteralPath $p -PathType Leaf) {
            $files.Add((Resolve-Path -LiteralPath $p).Path)
        }
        else {
            throw "IIS log path not found: $p"
        }
    }

    return $files
}

function Read-W3CLogSet {
    <#
        Reads and concatenates every log file under the given path(s).
        Reports whether all files declared the same #Fields: order, since
        a mismatch across rotated files is useful collection-quality
        information for the report rather than a silent inconsistency.

        -SinceDate is passed straight through to Get-W3CLogFileSet as a
        pre-filter over which files get parsed at all - see that
        function's comment for why it only ever skips files that
        provably cannot contain the target date, never the reverse.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Path,
        [datetime]$SinceDate
    )

    $fileSetParams = @{ Path = $Path }
    if ($SinceDate) { $fileSetParams['SinceDate'] = $SinceDate }
    $files = Get-W3CLogFileSet @fileSetParams
    $allRecords = New-Object System.Collections.Generic.List[object]
    $totalMalformed = 0
    $fieldSets = New-Object System.Collections.Generic.List[object]

    foreach ($file in $files) {
        $result = Read-W3CLogFile -Path $file
        $totalMalformed += $result.MalformedCount
        $fieldSets.Add([pscustomobject]@{ Path = $file; Fields = $result.Fields }) | Out-Null

        foreach ($record in $result.Records) {
            $allRecords.Add($record) | Out-Null
        }
    }

    $distinctFieldSets = $fieldSets |
        Where-Object { $_.Fields } |
        ForEach-Object { $_.Fields -join ',' } |
        Select-Object -Unique

    [pscustomobject]@{
        Files            = $files
        FieldSets        = $fieldSets
        FieldsConsistent = (@($distinctFieldSets).Count -le 1)
        Records          = $allRecords
        MalformedCount   = $totalMalformed
    }
}

function ConvertTo-NormalizedRequestRecord {
    <#
        Converts a raw (all-string) W3C record into a typed record with
        stable property names, independent of which fields the source log
        actually contained. A field that was absent from the log stays
        $null rather than being fabricated. "-" is IIS's placeholder for
        an empty value and is normalized to $null as well.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record
    )

    $props = $Record.PSObject.Properties.Name

    function Get-FieldValue([string]$name) {
        if ($props -contains $name) {
            $v = $Record.$name
            if ($v -eq '-') { return $null }
            return $v
        }
        return $null
    }

    $dateStr = Get-FieldValue 'date'
    $timeStr = Get-FieldValue 'time'
    $timestamp = $null

    if ($dateStr -and $timeStr) {
        $parsed = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse("$dateStr $timeStr", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            $timestamp = $parsed
        }
    }

    $statusRaw    = Get-FieldValue 'sc-status'
    $subStatusRaw = Get-FieldValue 'sc-substatus'
    $timeTakenRaw = Get-FieldValue 'time-taken'
    $csBytesRaw   = Get-FieldValue 'cs-bytes'
    $scBytesRaw   = Get-FieldValue 'sc-bytes'

    [pscustomobject]@{
        Timestamp     = $timestamp
        SiteName      = Get-FieldValue 's-sitename'
        Method        = Get-FieldValue 'cs-method'
        UriStem       = Get-FieldValue 'cs-uri-stem'
        UriQuery      = Get-FieldValue 'cs-uri-query'
        StatusCode    = if ($statusRaw) { [int]$statusRaw } else { $null }
        SubStatus     = if ($null -ne $subStatusRaw) { [int]$subStatusRaw } else { $null }
        Win32Status   = Get-FieldValue 'sc-win32-status'
        BytesReceived = if ($csBytesRaw) { [int64]$csBytesRaw } else { $null }
        BytesSent     = if ($scBytesRaw) { [int64]$scBytesRaw } else { $null }
        TimeTakenMs   = if ($timeTakenRaw) { [double]$timeTakenRaw } else { $null }
    }
}
