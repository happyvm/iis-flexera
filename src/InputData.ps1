# Safe loading of optional collector outputs with explicit data-quality state.

function Import-CollectionCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Path = $Path; Status = 'ABSENT'; Records = @(); Error = $null }
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        return [pscustomobject]@{ Path = $Path; Status = 'EMPTY'; Records = @(); Error = $null }
    }
    try {
        $records = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
        $status = if ($records.Count -eq 0) { 'EMPTY' } else { 'PRESENT' }
        return [pscustomobject]@{ Path = $Path; Status = $status; Records = $records; Error = $null }
    } catch {
        return [pscustomobject]@{ Path = $Path; Status = 'INVALID'; Records = @(); Error = $_.Exception.Message }
    }
}

function Import-CollectionJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Path = $Path; Status = 'ABSENT'; Data = $null; Error = $null }
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        return [pscustomobject]@{ Path = $Path; Status = 'EMPTY'; Data = $null; Error = $null }
    }
    try {
        $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $data) {
            return [pscustomobject]@{ Path = $Path; Status = 'EMPTY'; Data = $null; Error = $null }
        }
        return [pscustomobject]@{ Path = $Path; Status = 'PRESENT'; Data = $data; Error = $null }
    } catch {
        return [pscustomobject]@{ Path = $Path; Status = 'INVALID'; Data = $null; Error = $_.Exception.Message }
    }
}
