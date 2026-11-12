# Read-only regression: reproduce a legacy Chinese Windows console and ensure
# source checks work without changing the caller's encoding or Git metadata.
$ErrorActionPreference = 'Stop'
$savedConsoleEncoding = [Console]::OutputEncoding
$savedOutputEncoding = $OutputEncoding
try {
    [Console]::OutputEncoding = [Text.Encoding]::GetEncoding(936)
    $OutputEncoding = [Text.Encoding]::ASCII
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\publish-github.ps1'
    & $scriptPath -CheckOnly
    if ($LASTEXITCODE -ne 0) { throw 'Source check failed under code page 936.' }
    if ([Console]::OutputEncoding.CodePage -ne 936 -or $OutputEncoding.CodePage -ne 20127) {
        throw 'Publishing script did not restore the caller encoding.'
    }
    Write-Host "PASS PowerShell $($PSVersionTable.PSVersion): Chinese path with code page 936; encoding restored."
} finally {
    [Console]::OutputEncoding = $savedConsoleEncoding
    $OutputEncoding = $savedOutputEncoding
}
