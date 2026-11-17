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
    function Invoke-DockerInput {
        param([string]$InputText, [string[]]$DockerArgs)
        # Windows PowerShell's native argument quoting can strip embedded quotes.
        # Feed source on stdin instead of passing a JavaScript program through --eval.
        $InputText | & docker @DockerArgs
        if ($LASTEXITCODE -ne 0) { throw 'Docker input command failed. Keep the error above for diagnosis.' }
    }
    function Assert-Condition {
        param([bool]$Condition, [string]$Message)
        if (-not $Condition) { throw $Message }
    }
    $composeModel = Invoke-DockerChecked @composeArgs config --format json | ConvertFrom-Json
    $temporaryMounts = @($composeModel.services.app.tmpfs)
    Assert-Condition ($temporaryMounts.Count -eq 1 -and $temporaryMounts[0] -eq '/tmp:size=32m,noexec,nosuid') 'The temporary mount must preserve its size and security options as one entry.'
    $configuredAppNetworks = @($composeModel.services.app.networks.PSObject.Properties.Name)
    Assert-Condition ($configuredAppNetworks.Count -eq 1) 'The application must use exactly one internal backend network.'
    $backendName = $configuredAppNetworks[0]
    Assert-Condition ([bool]$composeModel.networks.PSObject.Properties[$backendName].Value.internal) 'The application backend network must be internal.'
    $configuredGatewayNetworks = @($composeModel.services.gateway.networks.PSObject.Properties.Name)
    $configuredIngress = @($configuredGatewayNetworks | Where-Object { -not [bool]$composeModel.networks.PSObject.Properties[$_].Value.internal })
    Assert-Condition ($configuredGatewayNetworks.Count -eq 2 -and $configuredGatewayNetworks -contains $backendName -and $configuredIngress.Count -eq 1) 'The gateway needs the shared backend and one non-internal ingress network to publish its HTTPS port.'
    Assert-Condition (Test-Path -LiteralPath 'node_modules/tsx/dist/cli.mjs') 'Run npm ci before verification.'
    if ($CheckOnly) { Write-Host 'PASS Compose configuration and local prerequisites. No engine access or containers changed.'; return }
    $engineType = (& docker info --format '{{.OSType}}')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot access the Docker engine. Run this script in your normal PowerShell terminal with Docker Desktop running.' }
    Assert-Condition ($engineType -eq 'linux') 'Docker Desktop must use Linux containers.'
    $privateDir = Join-Path $projectRoot '.local/container-check'
    New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $projectRoot 'reports') -Force | Out-Null
    foreach ($reportName in @('container-seed.json', 'container-resume.json', 'container-profile.json', 'container-runtime.json', 'container-latest.json')) {
        $reportFile = Join-Path $projectRoot "reports/$reportName"
        if (Test-Path -LiteralPath $reportFile) { Remove-Item -LiteralPath $reportFile }
    }
    $snapshotSource = Get-Content -LiteralPath 'scripts/data-snapshot.mjs' -Raw -Encoding UTF8
    $existingSnapshot = $null
    $existingApp = (Invoke-DockerChecked @composeArgs ps --quiet app)
    if ($existingApp) {
        # Runs against the old image too: the source uses only built-in Node modules.
        # Capture only row fingerprints; no password hashes, names or tokens are printed.
        $snapshotArgs = $composeArgs + @('exec', '--no-TTY', 'app', 'node', '--input-type=module')
        $existingSnapshot = (Invoke-DockerInput -InputText $snapshotSource -DockerArgs $snapshotArgs | ConvertFrom-Json)
    }
    Write-Host 'Building and starting isolated project safedrop-check on https://localhost:18443 ...'
    # Mounted Caddyfile changes require a new process even if its path is stable.
    # Recreating these verification containers preserves their named data volumes.
    Invoke-DockerChecked @composeArgs up --build --force-recreate --detach --wait --wait-timeout 180
    $existingData = [ordered]@{ checked = $false; records = 0 }
    if ($null -ne $existingSnapshot) {
        $snapshotArgs = $composeArgs + @('exec', '--no-TTY', 'app', 'node', '--input-type=module')
        $upgradedSnapshot = (Invoke-DockerInput -InputText $snapshotSource -DockerArgs $snapshotArgs | ConvertFrom-Json)
        foreach ($table in $existingSnapshot.tables.PSObject.Properties) {
            $upgradedTable = $upgradedSnapshot.tables.PSObject.Properties[$table.Name].Value
            foreach ($record in $table.Value.PSObject.Properties) {
                $upgradedRecord = $upgradedTable.PSObject.Properties[$record.Name]
                Assert-Condition ($null -ne $upgradedRecord -and $upgradedRecord.Value -eq $record.Value) "Existing $($table.Name) data changed during upgrade. Stop and inspect the retained data volume."
                $existingData.records++
            }
        }
        $existingData.checked = $true
        Write-Host "PASS upgrade preserved $($existingData.records) existing database records (session revocation on restart is expected)."
    }
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
    # Save only non-secret configuration so a failed check can be diagnosed.
    $runtimeEvidence = [ordered]@{ created = [DateTime]::UtcNow.ToString('o'); appUser = $appInfo.Config.User; appNetworks = @($appInfo.NetworkSettings.Networks.PSObject.Properties.Name); gatewayNetworks = @($gatewayInfo.NetworkSettings.Networks.PSObject.Properties.Name); gatewayRequestedPorts = $gatewayInfo.HostConfig.PortBindings; gatewayPublishedPorts = $gatewayInfo.NetworkSettings.Ports }
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-runtime.json'), ($runtimeEvidence | ConvertTo-Json -Depth 6), $utf8)
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
    $gatewayNetworks = @($gatewayInfo.NetworkSettings.Networks.PSObject.Properties.Name)
    $ingressNames = @($gatewayNetworks | Where-Object { $_ -ne $networkNames[0] })
    Assert-Condition ($gatewayNetworks.Count -eq 2 -and $gatewayNetworks -contains $networkNames[0] -and $ingressNames.Count -eq 1) 'The gateway needs the backend and a separate ingress network.'
    $ingressInfo = @(Invoke-DockerChecked network inspect $ingressNames[0] | ConvertFrom-Json)[0]
    Assert-Condition (-not [bool]$ingressInfo.Internal) 'The gateway ingress network must permit host port publishing.'
    $ports = @($gatewayInfo.NetworkSettings.Ports.'8443/tcp' | Where-Object { $null -ne $_ })
    $portDescription = ConvertTo-Json -InputObject $ports -Compress -Depth 3
    Assert-Condition ($ports.Count -gt 0) "The gateway HTTPS port was not published. Observed: $portDescription. See reports/container-runtime.json."
    Assert-Condition ($ports.Count -eq 1 -and $ports[0].HostIp -eq '127.0.0.1' -and $ports[0].HostPort -eq '18443') "Unexpected gateway port binding: $portDescription. Expected only 127.0.0.1:18443."
    $profile = [ordered]@{ created = [DateTime]::UtcNow.ToString('o'); ok = $true; checks = @('Non-root application', 'Read-only roots', 'All capabilities dropped', 'Privilege escalation disabled', 'Memory/CPU/PID limits', 'Internal backend without published app ports', 'Separate gateway ingress network', 'Loopback-only gateway') }
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
    $summary = [ordered]@{ version = 4; created = [DateTime]::UtcNow.ToString('o'); ok = $true; project = 'safedrop-check'; origin = 'https://localhost:18443'; existingData = $existingData; profile = $profile; before = (Get-Content -LiteralPath 'reports/container-seed.json' -Raw -Encoding UTF8 | ConvertFrom-Json); after = (Get-Content -LiteralPath 'reports/container-resume.json' -Raw -Encoding UTF8 | ConvertFrom-Json); stableAccounts = $true; stableCA = $true }
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
