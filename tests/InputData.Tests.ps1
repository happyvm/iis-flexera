BeforeAll { . "$PSScriptRoot/../src/InputData.ps1" }

Describe 'collector input state detection' {
    It 'distinguishes absent, empty and invalid files' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ("iis-input-{0}" -f [guid]::NewGuid())
        New-Item -ItemType Directory -Path $root | Out-Null
        try {
            (Import-CollectionCsv (Join-Path $root 'absent.csv')).Status | Should -Be 'ABSENT'
            Set-Content (Join-Path $root 'empty.csv') -Value '' -NoNewline
            (Import-CollectionCsv (Join-Path $root 'empty.csv')).Status | Should -Be 'EMPTY'
            Set-Content (Join-Path $root 'bad.json') -Value '{not-json}'
            (Import-CollectionJson (Join-Path $root 'bad.json')).Status | Should -Be 'INVALID'
        } finally { Remove-Item $root -Recurse -Force }
    }
}
