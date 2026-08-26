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

        Opens with FileShare.ReadWrite/Delete rather than .NET's default
        FileShare.Read, and retries briefly on a sharing violation, so a
        file IIS itself currently has open for writing - most commonly
        today's active log - can still be read instead of throwing "The
        process cannot access the file... being used by another
        process." Still throws if the file cannot be opened after
        retrying; Read-W3CLogSet treats that as a per-file warning rather
        than aborting the whole multi-file read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxOpenAttempts = 4,
        [int]$RetryDelayMilliseconds = 250
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "IIS log file not found: $Path"
    }

    $reader = $null
    $attempt = 0
    while (-not $reader) {
        $attempt++
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
            $reader = New-Object System.IO.StreamReader($stream)
        } catch [System.IO.IOException] {
            if ($attempt -ge $MaxOpenAttempts) { throw }
            Start-Sleep -Milliseconds $RetryDelayMilliseconds
        }
    }

    $fields = $null
    $malformedCount = 0
    $records = New-Object System.Collections.Generic.List[psobject]

    try {
        while ($null -ne ($line = $reader.ReadLine())) {
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
    } finally {
        $reader.Dispose()
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

        -SinceDate is an optional pre-filter for directory expansion only
        (an explicitly named file is always included - the caller
        pointed at it on purpose), built from two independently-safe
        checks that can only ever reduce work, never silently drop data
        (Select-ByDate on the parsed records remains the authoritative
        filter either way):
          - skip a file whose LastWriteTime is before that date: an
            append-only IIS log can't contain entries from that date or
            later without having been written to on or after it;
          - skip a file whose CreationTime is on/after the day *after*
            that date (or after -UntilDate, when a period is requested):
            nothing in a file can predate the file's own creation, so it
            cannot hold entries from a day that had already ended before
            the file existed. This is what keeps a query for yesterday
            from touching today's still-open, actively-written log file.
        Neither check assumes a rotation period (Daily/Weekly/Monthly/
        Unlimited/MaxSize): a file whose CreationTime predates the target
        day and whose LastWriteTime is on/after it is always kept,
        because it could plausibly span into that day regardless of how
        the admin configured rollover.

        -UntilDate widens the window to a period [SinceDate, UntilDate]
        instead of a single day, and requires -SinceDate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Path,
        [datetime]$SinceDate,
        [datetime]$UntilDate
    )

    if ($UntilDate -and -not $SinceDate) {
        throw '-UntilDate requires -SinceDate.'
    }

    $files = New-Object System.Collections.Generic.List[string]

    foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            $candidates = Get-ChildItem -LiteralPath $p -Filter '*.log' -File
            if ($SinceDate) {
                $dayStart = $SinceDate.Date
                $dayAfter = if ($UntilDate) { $UntilDate.Date.AddDays(1) } else { $dayStart.AddDays(1) }
                $candidates = $candidates | Where-Object {
                    ($_.LastWriteTime -ge $dayStart) -and ($_.CreationTime -lt $dayAfter)
                }
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

        -SinceDate and -UntilDate are passed straight through to
        Get-W3CLogFileSet as a pre-filter over which files get parsed at
        all - see that function's comment for why it only ever skips
        files that provably cannot contain the target date/period, never
        the reverse.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Path,
        [datetime]$SinceDate,
        [datetime]$UntilDate
    )

    $fileSetParams = @{ Path = $Path }
    if ($SinceDate) { $fileSetParams['SinceDate'] = $SinceDate }
    if ($UntilDate) { $fileSetParams['UntilDate'] = $UntilDate }
    $files = Get-W3CLogFileSet @fileSetParams
    $allRecords = New-Object System.Collections.Generic.List[psobject]
    $totalMalformed = 0
    $fieldSets = New-Object System.Collections.Generic.List[psobject]
    $unreadableFiles = New-Object System.Collections.Generic.List[psobject]

    foreach ($file in $files) {
        try {
            $result = Read-W3CLogFile -Path $file
        } catch {
            # A single locked/unreadable file (e.g. today's active log,
            # momentarily locked by IIS) does not abort the whole
            # multi-file read - "fail partially, not completely".
            $unreadableFiles.Add([pscustomobject]@{ Path = $file; Error = $_.Exception.Message }) | Out-Null
            continue
        }

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
        UnreadableFiles  = $unreadableFiles.ToArray()
    }
}

function Get-W3CFieldValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Record.PSObject.Properties[$Name]
    if (-not $property -or $property.Value -eq '-') { return $null }
    return $property.Value
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

    $dateStr = Get-W3CFieldValue -Record $Record -Name 'date'
    $timeStr = Get-W3CFieldValue -Record $Record -Name 'time'
    $timestamp = $null

    if ($dateStr -and $timeStr) {
        $timestamp = ConvertTo-UtcDateTime -Value "$dateStr $timeStr" -UnspecifiedKind UnspecifiedAsUtc
    }

    $statusRaw    = Get-W3CFieldValue -Record $Record -Name 'sc-status'
    $subStatusRaw = Get-W3CFieldValue -Record $Record -Name 'sc-substatus'
    $timeTakenRaw = Get-W3CFieldValue -Record $Record -Name 'time-taken'
    $csBytesRaw   = Get-W3CFieldValue -Record $Record -Name 'cs-bytes'
    $scBytesRaw   = Get-W3CFieldValue -Record $Record -Name 'sc-bytes'

    [pscustomobject]@{
        Timestamp     = $timestamp
        SiteName      = Get-W3CFieldValue -Record $Record -Name 's-sitename'
        Method        = Get-W3CFieldValue -Record $Record -Name 'cs-method'
        UriStem       = Get-W3CFieldValue -Record $Record -Name 'cs-uri-stem'
        UriQuery      = Get-W3CFieldValue -Record $Record -Name 'cs-uri-query'
        ClientIp      = Get-W3CFieldValue -Record $Record -Name 'c-ip'
        ServerIp      = Get-W3CFieldValue -Record $Record -Name 's-ip'
        UserAgent     = Get-W3CFieldValue -Record $Record -Name 'cs(User-Agent)'
        AuthenticatedUser = Get-W3CFieldValue -Record $Record -Name 'cs-username'
        Host           = Get-W3CFieldValue -Record $Record -Name 'cs-host'
        ProtocolVersion = Get-W3CFieldValue -Record $Record -Name 'cs-version'
        StatusCode    = if ($statusRaw) { [int]$statusRaw } else { $null }
        SubStatus     = if ($null -ne $subStatusRaw) { [int]$subStatusRaw } else { $null }
        Win32Status   = Get-W3CFieldValue -Record $Record -Name 'sc-win32-status'
        BytesReceived = if ($csBytesRaw) { [int64]$csBytesRaw } else { $null }
        BytesSent     = if ($scBytesRaw) { [int64]$scBytesRaw } else { $null }
        TimeTakenMs   = if ($timeTakenRaw) { [double]$timeTakenRaw } else { $null }
    }
}
