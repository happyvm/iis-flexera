BeforeAll {
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
