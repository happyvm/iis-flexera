BeforeAll {
    . "$PSScriptRoot/../src/Time.ps1"
    . "$PSScriptRoot/../src/IisLogs.ps1"
    $fixtureDir = Join-Path $PSScriptRoot '../fixtures/iis-logs'
}

Describe 'ConvertFrom-W3CFieldsLine' {
    It 'parses a #Fields: header into an ordered field list' {
        $fields = ConvertFrom-W3CFieldsLine -Line '#Fields: date time s-sitename cs-method cs-uri-stem'
        $fields | Should -Be @('date', 'time', 's-sitename', 'cs-method', 'cs-uri-stem')
    }

    It 'throws for a non-#Fields: line' {
        { ConvertFrom-W3CFieldsLine -Line '#Software: Microsoft Internet Information Services 10.0' } | Should -Throw
    }
}

Describe 'Read-W3CLogFile' {
    It 'parses a standard field-order log fixture, skipping comment lines' {
        $result = Read-W3CLogFile -Path (Join-Path $fixtureDir 'standard-fields.log')
        $result.Fields | Should -Contain 'time-taken'
        $result.RecordCount | Should -Be 3
        $result.MalformedCount | Should -Be 0
        $result.Records[0].'cs-uri-stem' | Should -Be '/ManageSoftRL/upload.aspx'
    }

    It 'parses a log fixture with a different #Fields: order' {
        $result = Read-W3CLogFile -Path (Join-Path $fixtureDir 'alt-field-order.log')
        $result.Fields[0] | Should -Be 'date'
        $result.RecordCount | Should -Be 2
        $result.Records[0].'cs-uri-stem' | Should -Be '/ManageSoftDL/agent.osd'
    }

    It 'skips malformed rows without throwing' {
        $result = Read-W3CLogFile -Path (Join-Path $fixtureDir 'malformed.log')
        $result.MalformedCount | Should -BeGreaterThan 0
        $result.RecordCount | Should -Be 1
    }

    It 'throws for a missing file' {
        { Read-W3CLogFile -Path (Join-Path $fixtureDir 'does-not-exist.log') } | Should -Throw
    }

    It 'reads a file another handle holds open for writing, like IIS actively logging to it' {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("iis-flexera-locktest-{0}.log" -f ([guid]::NewGuid()))
        Set-Content -Path $tempFile -Value "#Fields: date time cs-method`n2026-08-26 00:00:01 GET"

        $lockStream = [System.IO.File]::Open($tempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        try {
            $result = Read-W3CLogFile -Path $tempFile
            $result.RecordCount | Should -Be 1
        }
        finally {
            $lockStream.Dispose()
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    It 'throws after retrying when the file stays exclusively locked' {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("iis-flexera-locktest-{0}.log" -f ([guid]::NewGuid()))
        Set-Content -Path $tempFile -Value "#Fields: date time`n2026-08-26 00:00:01 12:00:00"

        $lockStream = [System.IO.File]::Open($tempFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            { Read-W3CLogFile -Path $tempFile -MaxOpenAttempts 2 -RetryDelayMilliseconds 10 } | Should -Throw
        }
        finally {
            $lockStream.Dispose()
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Read-W3CLogSet' {
    It 'combines multiple log files covering the observation period' {
        $result = Read-W3CLogSet -Path @(
            (Join-Path $fixtureDir 'standard-fields.log'),
            (Join-Path $fixtureDir 'alt-field-order.log')
        )
        $result.Records.Count | Should -Be 5
        $result.Files.Count | Should -Be 2
    }

    It 'flags inconsistent #Fields: definitions across files' {
        $result = Read-W3CLogSet -Path @(
            (Join-Path $fixtureDir 'standard-fields.log'),
            (Join-Path $fixtureDir 'alt-field-order.log')
        )
        $result.FieldsConsistent | Should -Be $false
    }

    It 'expands a directory into its *.log files' {
        $result = Read-W3CLogSet -Path @($fixtureDir)
        $result.Files.Count | Should -Be 3
    }

    It 'skips an unreadable (locked) file, keeps the rest, and reports it rather than aborting' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("iis-flexera-locktest-{0}" -f ([guid]::NewGuid()))
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        $goodFile = Join-Path $dir 'u_ex260825.log'
        $lockedFile = Join-Path $dir 'u_ex260826.log'
        Set-Content -Path $goodFile -Value "#Fields: date time`n2026-08-25 00:00:01"
        Set-Content -Path $lockedFile -Value "#Fields: date time`n2026-08-26 00:00:01"

        $lockStream = [System.IO.File]::Open($lockedFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $result = Read-W3CLogSet -Path @($dir)
            $result.Records.Count | Should -Be 1
            $result.UnreadableFiles.Count | Should -Be 1
            $result.UnreadableFiles[0].Path | Should -Match 'u_ex260826\.log$'
        }
        finally {
            $lockStream.Dispose()
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-W3CLogFileSet -SinceDate pre-filter' {
    BeforeEach {
        $logDir = Join-Path ([System.IO.Path]::GetTempPath()) ("iis-flexera-logtest-{0}" -f ([guid]::NewGuid()))
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null

        $oldFile = Join-Path $logDir 'u_ex260818.log'
        $targetFile = Join-Path $logDir 'u_ex260820.log'
        Set-Content -Path $oldFile -Value '#Fields: date time'
        Set-Content -Path $targetFile -Value '#Fields: date time'

        (Get-Item $oldFile).LastWriteTime = (Get-Date '2026-08-18T23:00:00')
        (Get-Item $targetFile).LastWriteTime = (Get-Date '2026-08-20T23:00:00')
    }

    AfterEach {
        Remove-Item -LiteralPath $logDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'includes every *.log file in a directory when no -SinceDate is given' {
        $files = @(Get-W3CLogFileSet -Path @($logDir))
        $files.Count | Should -Be 2
    }

    It 'skips a file last written before -SinceDate' {
        $files = @(Get-W3CLogFileSet -Path @($logDir) -SinceDate (Get-Date '2026-08-20'))
        $files.Count | Should -Be 1
        $files[0] | Should -Match 'u_ex260820\.log$'
    }

    It 'never skips an explicitly named file, even if written before -SinceDate' {
        $oldFile = Join-Path $logDir 'u_ex260818.log'
        $files = @(Get-W3CLogFileSet -Path @($oldFile) -SinceDate (Get-Date '2026-08-20'))
        $files.Count | Should -Be 1
    }

    It 'skips a file created after the target day, e.g. tomorrow''s still-open log' {
        $futureFile = Join-Path $logDir 'u_ex260821.log'
        Set-Content -Path $futureFile -Value '#Fields: date time'
        (Get-Item $futureFile).CreationTime = (Get-Date '2026-08-21T00:00:05')
        (Get-Item $futureFile).LastWriteTime = (Get-Date '2026-08-21T08:00:00')

        # LastWriteTime alone would keep this file (it is on/after -SinceDate);
        # only the CreationTime check should exclude it.
        $files = @(Get-W3CLogFileSet -Path @($logDir) -SinceDate (Get-Date '2026-08-20'))
        $files | Where-Object { $_ -match 'u_ex260821\.log$' } | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-NormalizedRequestRecord' {
    It 'normalizes typed fields and treats "-" as null' {
        $raw = Read-W3CLogFile -Path (Join-Path $fixtureDir 'standard-fields.log')
        $normalized = ConvertTo-NormalizedRequestRecord -Record $raw.Records[0]
        $normalized.UriStem | Should -Be '/ManageSoftRL/upload.aspx'
        $normalized.UriQuery | Should -BeNullOrEmpty
        $normalized.TimeTakenMs | Should -Be 142
        $normalized.StatusCode | Should -Be 200
    }

    It 'leaves a field null when the source log did not include it' {
        $record = [pscustomobject]@{ date = '2026-08-19'; time = '00:00:03'; 'cs-uri-stem' = '/ManageSoftDL/policy.xml' }
        $normalized = ConvertTo-NormalizedRequestRecord -Record $record
        $normalized.TimeTakenMs | Should -BeNullOrEmpty
        $normalized.StatusCode | Should -BeNullOrEmpty
    }
}

Describe 'optional W3C fields' {
    It 'normalizes diagnostic fields when present without requiring them' {
        $record = [pscustomobject]@{
            date='2026-08-26'; time='12:00:00'; 'c-ip'='10.0.0.1'; 's-ip'='10.0.0.2'
            'cs(User-Agent)'='Flexera-Agent'; 'cs-username'='-'; 'cs-host'='beacon.example'; 'cs-version'='HTTP/1.1'
        }
        $result = ConvertTo-NormalizedRequestRecord $record
        $result.Timestamp.Kind | Should -Be ([DateTimeKind]::Utc)
        $result.ClientIp | Should -Be '10.0.0.1'
        $result.AuthenticatedUser | Should -BeNullOrEmpty
        $result.ProtocolVersion | Should -Be 'HTTP/1.1'
    }
}
