# Run in a normal PowerShell terminal. This script never changes access controls,
# rewrites existing commits, force-pushes, or stores authentication credentials.
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$CommitOnly)
$ErrorActionPreference = 'Stop'
$previousConsoleEncoding = [Console]::OutputEncoding
$previousOutputEncoding = $OutputEncoding
try {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $utf8
    $OutputEncoding = $utf8
    $targetRemote = 'https://github.com/logic-xx/safedrop.git'
    $projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    Set-Location -LiteralPath $projectRoot

    function Invoke-GitChecked {
        param([Parameter(ValueFromRemainingArguments=$true)][string[]]$GitArgs)
        & git @GitArgs
        if ($LASTEXITCODE -ne 0) { throw "Git failed: $($GitArgs[0]). No force-push or history rewrite was attempted." }
    }

    $gitRoot = (& git rev-parse --show-toplevel).Trim()
    if ($LASTEXITCODE -ne 0 -or (Resolve-Path -LiteralPath $gitRoot).Path -ne $projectRoot) {
        throw 'The script must run from its original SafeDrop Git working tree.'
    }
    $branch = (& git branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -ne 'main') { throw 'Expected the main branch. Inspect the current branch before publishing.' }

    $files = @(& git -c core.quotepath=false ls-files -co --exclude-standard | Sort-Object -Unique)
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate source files.' }
    $sensitivePath = '(^|/)(\.local|tmp|node_modules|\.npm-cache)(/|$)|^notes/private/|(^|/)\.env($|\.)|\.(key|pem|pfx|p12)$|(^|/)accounts\.json$'
    $keyContent = '(?m)^-----BEGIN (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----\s*$'
    $tokenContent = '\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'
    foreach ($relativePath in $files) {
        if (-not (Test-Path -LiteralPath $relativePath -PathType Leaf)) { continue }
        if ($relativePath -match $sensitivePath) { throw "Sensitive file in source candidates: $relativePath" }
        if ([IO.Path]::GetExtension($relativePath) -match '^\.(jpg|jpeg|png|gif|ico)$') { continue }
        $content = [IO.File]::ReadAllText((Join-Path $projectRoot $relativePath), [Text.Encoding]::UTF8)
        if ($content -match $keyContent -or $content -match $tokenContent) { throw "Possible private key or credential in: $relativePath" }
    }
    Invoke-GitChecked diff --check
    Write-Host "Source check passed. Destination: $targetRemote"
    Invoke-GitChecked status --short --branch
    if ($CheckOnly) { Write-Host 'Check only: no configuration, commits or uploads changed.'; exit 0 }

    $remotes = @(& git remote)
    if ($remotes -contains 'origin') {
        $existing = (& git remote get-url origin).Trim()
        if ($existing -notin @($targetRemote, 'https://github.com/logic-xx/safedrop', 'git@github.com:logic-xx/safedrop.git')) {
            throw "Existing origin differs from the intended repository. Review it before continuing."
        }
    } else { Invoke-GitChecked remote add origin $targetRemote }

    Invoke-GitChecked add --all
    # Check the actual index as well as the working tree before committing.
    $staged = @(& git -c core.quotepath=false diff --cached --name-only --diff-filter=ACMR)
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the staging area.' }
    foreach ($path in $staged) { if ($path -match $sensitivePath) { throw "Sensitive staged file: $path" } }
    & git diff --cached --quiet
    if ($LASTEXITCODE -eq 1) {
        Invoke-GitChecked commit -m 'feat: add secure file transfer, session controls and verifiable audit'
    } elseif ($LASTEXITCODE -ne 0) { throw 'Could not inspect staged changes.' }

    if ($CommitOnly) {
        Write-Host 'Local commit ready. Push manually with: git push -u origin main'
        exit 0
    }

    # Normal push preserves local history and refuses to overwrite unrelated changes.
    Invoke-GitChecked push -u origin main
    Write-Host 'Published to https://github.com/logic-xx/safedrop'

} finally {
    [Console]::OutputEncoding = $previousConsoleEncoding
    $OutputEncoding = $previousOutputEncoding
}
