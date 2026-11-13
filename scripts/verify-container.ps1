#Requires -Version 5.1
# Run in a normal PowerShell terminal. Uses an isolated Compose project and data.
[CmdletBinding()]
param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
$previousConsoleEncoding = [Console]::OutputEncoding
$previousOutputEncoding = $OutputEncoding
$previousLocation = Get-Location
try {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $utf8
    $OutputEncoding = $utf8
    $projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    Set-Location -LiteralPath $projectRoot
    $composeArgs = @('compose', '--project-name', 'safedrop-check', '--file', 'compose.yaml', '--file', 'deploy/compose.verify.yaml')
    function Invoke-DockerChecked {
        param([Parameter(ValueFromRemainingArguments=$true)][string[]]$DockerArgs)
        & docker @DockerArgs
        if ($LASTEXITCODE -ne 0) { throw 'Docker command failed. Keep the error above for diagnosis.' }
    }
    function Assert-Condition {
        param([bool]$Condition, [string]$Message)
        if (-not $Condition) { throw $Message }
    }
    $composeModel = Invoke-DockerChecked @composeArgs config --format json | ConvertFrom-Json
    $temporaryMounts = @($composeModel.services.app.tmpfs)
    Assert-Condition ($temporaryMounts.Count -eq 1 -and $temporaryMounts[0] -eq '/tmp:size=32m,noexec,nosuid') 'The temporary mount must preserve its size and security options as one entry.'
    Assert-Condition (Test-Path -LiteralPath 'node_modules/tsx/dist/cli.mjs') 'Run npm ci before verification.'
    if ($CheckOnly) { Write-Host 'PASS Compose configuration and local prerequisites. No engine access or containers changed.'; return }
    $engineType = (& docker info --format '{{.OSType}}')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot access the Docker engine. Run this script in your normal PowerShell terminal with Docker Desktop running.' }
    Assert-Condition ($engineType -eq 'linux') 'Docker Desktop must use Linux containers.'
    $privateDir = Join-Path $projectRoot '.local/container-check'
    New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $projectRoot 'reports') -Force | Out-Null
    foreach ($reportName in @('container-seed.json', 'container-resume.json', 'container-profile.json', 'container-latest.json')) {
        $reportFile = Join-Path $projectRoot "reports/$reportName"
        if (Test-Path -LiteralPath $reportFile) { Remove-Item -LiteralPath $reportFile }
    }
    Write-Host 'Building and starting isolated project safedrop-check on https://localhost:18443 ...'
    Invoke-DockerChecked @composeArgs up --build --detach --wait --wait-timeout 180
    $certificateReady = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        # Caddy creates its local CA during first startup. Copy only the public CA.
        $savedErrorPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & docker @composeArgs cp 'gateway:/data/caddy/pki/authorities/local/root.crt' (Join-Path $privateDir 'ca.crt') 2>$null
            $copyExitCode = $LASTEXITCODE
        } finally { $ErrorActionPreference = $savedErrorPreference }
        if ($copyExitCode -eq 0) { $certificateReady = $true; break }
        Start-Sleep -Seconds 1
    }
    Assert-Condition $certificateReady 'The gateway did not create its public CA certificate.'
    Invoke-DockerChecked @composeArgs cp 'app:/data/accounts.json' (Join-Path $privateDir 'accounts.json')
    # Credentials remain in the ignored .local directory and are never printed.
    $accountsHash = (Get-FileHash -LiteralPath (Join-Path $privateDir 'accounts.json') -Algorithm SHA256).Hash
    $caHash = (Get-FileHash -LiteralPath (Join-Path $privateDir 'ca.crt') -Algorithm SHA256).Hash
    $appId = (Invoke-DockerChecked @composeArgs ps --quiet app).Trim()
    $gatewayId = (Invoke-DockerChecked @composeArgs ps --quiet gateway).Trim()
    $appInfo = @(Invoke-DockerChecked inspect $appId | ConvertFrom-Json)[0]
    $gatewayInfo = @(Invoke-DockerChecked inspect $gatewayId | ConvertFrom-Json)[0]
    Assert-Condition ($appInfo.Config.User -eq '10001:10001') 'The application is not running as UID/GID 10001.'
    foreach ($serviceInfo in @($appInfo, $gatewayInfo)) {
        Assert-Condition ([bool]$serviceInfo.HostConfig.ReadonlyRootfs) 'A container root filesystem is writable.'
        Assert-Condition ($serviceInfo.HostConfig.CapDrop -contains 'ALL') 'A container has not dropped all capabilities.'
        Assert-Condition (@($serviceInfo.HostConfig.SecurityOpt | Where-Object { $_ -match '^no-new-privileges(:true)?$' }).Count -gt 0) 'Privilege escalation is not disabled.'
        Assert-Condition ($serviceInfo.HostConfig.Memory -gt 0 -and $serviceInfo.HostConfig.NanoCpus -gt 0 -and $serviceInfo.HostConfig.PidsLimit -gt 0) 'Container resource limits are missing.'
    }
    $appPublished = @($appInfo.NetworkSettings.Ports.PSObject.Properties | Where-Object { $null -ne $_.Value })
    Assert-Condition ($appPublished.Count -eq 0) 'The application has a published host port.'
    $networkNames = @($appInfo.NetworkSettings.Networks.PSObject.Properties.Name)
    Assert-Condition ($networkNames.Count -eq 1) 'The application is attached to unexpected networks.'
    $networkInfo = @(Invoke-DockerChecked network inspect $networkNames[0] | ConvertFrom-Json)[0]
    Assert-Condition ([bool]$networkInfo.Internal) 'The backend network is not internal.'
    $ports = @($gatewayInfo.NetworkSettings.Ports.'8443/tcp')
    Assert-Condition ($ports.Count -eq 1 -and $ports[0].HostIp -eq '127.0.0.1' -and $ports[0].HostPort -eq '18443') 'The gateway is not restricted to the verification loopback port.'
    $profile = [ordered]@{ created = [DateTime]::UtcNow.ToString('o'); ok = $true; checks = @('Non-root application', 'Read-only roots', 'All capabilities dropped', 'Privilege escalation disabled', 'Memory/CPU/PID limits', 'Internal backend without published app ports', 'Loopback-only gateway') }
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-profile.json'), ($profile | ConvertTo-Json -Depth 4), $utf8)
    & node 'node_modules/tsx/dist/cli.mjs' 'tests/container-smoke.ts' seed $privateDir
    if ($LASTEXITCODE -ne 0) { throw 'HTTPS/WSS transfer checks failed before restart.' }
    Write-Host 'Restarting the verification containers while retaining their data volumes ...'
    Invoke-DockerChecked @composeArgs restart app gateway
    & node 'node_modules/tsx/dist/cli.mjs' 'tests/container-smoke.ts' resume $privateDir
    if ($LASTEXITCODE -ne 0) { throw 'Persistence or resume checks failed after restart.' }
    Invoke-DockerChecked @composeArgs cp 'app:/data/accounts.json' (Join-Path $privateDir 'accounts-after.json')
    Invoke-DockerChecked @composeArgs cp 'gateway:/data/caddy/pki/authorities/local/root.crt' (Join-Path $privateDir 'ca-after.crt')
    Assert-Condition ((Get-FileHash -LiteralPath (Join-Path $privateDir 'accounts-after.json') -Algorithm SHA256).Hash -eq $accountsHash) 'Generated credentials changed after restart.'
    Assert-Condition ((Get-FileHash -LiteralPath (Join-Path $privateDir 'ca-after.crt') -Algorithm SHA256).Hash -eq $caHash) 'The gateway CA changed after restart.'
    $summary = [ordered]@{ created = [DateTime]::UtcNow.ToString('o'); ok = $true; project = 'safedrop-check'; origin = 'https://localhost:18443'; profile = $profile; before = (Get-Content -LiteralPath 'reports/container-seed.json' -Raw -Encoding UTF8 | ConvertFrom-Json); after = (Get-Content -LiteralPath 'reports/container-resume.json' -Raw -Encoding UTF8 | ConvertFrom-Json); stableAccounts = $true; stableCA = $true }
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-latest.json'), ($summary | ConvertTo-Json -Depth 8), $utf8)
    Invoke-DockerChecked @composeArgs ps
    Write-Host 'PASS container verification. Report: reports/container-latest.json'
    Write-Host 'Verification containers remain running. Credentials and CA are under .local/container-check (do not share).'
    Write-Host 'Stop without deleting data: docker compose -p safedrop-check -f compose.yaml -f deploy/compose.verify.yaml down'
} finally {
    Set-Location -LiteralPath $previousLocation
    [Console]::OutputEncoding = $previousConsoleEncoding
    $OutputEncoding = $previousOutputEncoding
}
