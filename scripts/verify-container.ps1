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
    $configuredScanner = $composeModel.services.scanner
    $scannerNetworks = @($configuredScanner.networks.PSObject.Properties.Name)
    Assert-Condition ($configuredScanner.user -eq '65532:65532' -and [bool]$configuredScanner.read_only) 'The scanner must have a non-root identity and read-only root.'
    Assert-Condition (@($configuredScanner.ports | Where-Object { $null -ne $_ }).Count -eq 0) 'The unauthenticated scanner must not publish a host port.'
    Assert-Condition ($scannerNetworks.Count -eq 2 -and $scannerNetworks -contains $backendName -and $scannerNetworks -contains 'signatures') 'The scanner requires the backend and isolated signature-update egress.'
    $scannerVolumes = @($configuredScanner.volumes)
    Assert-Condition ($scannerVolumes.Count -eq 1 -and $scannerVolumes[0].type -eq 'volume' -and $scannerVolumes[0].source -eq 'scanner_data' -and $scannerVolumes[0].target -eq '/data') 'The scanner may mount only its own signature data volume.'
    Assert-Condition ($composeModel.services.app.environment.CLAMD_HOST -eq 'scanner') 'Application scanning must use the isolated scanner service.'
    Assert-Condition (Test-Path -LiteralPath 'node_modules/tsx/dist/cli.mjs') 'Run npm ci before verification.'
    if ($CheckOnly) { Write-Host 'PASS Compose configuration and local prerequisites. No engine access or containers changed.'; return }
    $engineType = (& docker info --format '{{.OSType}}')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot access the Docker engine. Run this script in your normal PowerShell terminal with Docker Desktop running.' }
    Assert-Condition ($engineType -eq 'linux') 'Docker Desktop must use Linux containers.'
    $privateDir = Join-Path $projectRoot '.local/container-check'
    New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $projectRoot 'reports') -Force | Out-Null
    # Prepare a dedicated context containing only the pinned public vendor archive.
    # A verified existing local package is reused; downloads occur on the host with resume.
    Write-Host 'Preparing the pinned scanner package; a verified local cache is reused when available ...'
    $vendorInputJson = & node 'scripts/prepare-scanner-vendor.mjs'
    if ($LASTEXITCODE -ne 0) { throw 'Scanner vendor input preparation failed. Existing containers and data remain unchanged.' }
    $vendorInput = $vendorInputJson | ConvertFrom-Json
    Assert-Condition ([bool]$vendorInput.ok) 'The scanner vendor package was not verified.'
    $composeBuildArgs = $composeArgs + @('--file', [string]$vendorInput.override)
    $buildModel = Invoke-DockerChecked @composeBuildArgs config --format json | ConvertFrom-Json
    Assert-Condition ($buildModel.services.scanner.build.args.REQUIRE_LOCAL_VENDOR -eq '1') 'Verification must require the local verified package input.'
    $buildContexts = @($buildModel.services.scanner.build.additional_contexts.PSObject.Properties)
    Assert-Condition ($buildContexts.Count -eq 1 -and $buildContexts[0].Name -eq 'vendor_package' -and [IO.Path]::GetFullPath([string]$buildContexts[0].Value) -eq [IO.Path]::GetFullPath([string]$vendorInput.context)) 'Unexpected scanner build context.'
    Write-Host "PASS verified scanner vendor cache ($($vendorInput.bytes) bytes, $($vendorInput.from)); build will not redownload it."
    $scannerBuildInput = [ordered]@{ verified = $true; bytes = $vendorInput.bytes; sha256 = $vendorInput.sha256; source = $vendorInput.from; localContextRequired = $true }
    foreach ($reportName in @('container-seed.json', 'container-resume.json', 'container-profile.json', 'container-runtime.json', 'container-mfa.json', 'container-gateway.json', 'container-backup.json', 'container-scan.json', 'container-scanner-provenance.json', 'container-delivery-expiry.json', 'container-latest.json')) {
        $reportFile = Join-Path $projectRoot "reports/$reportName"
        if (Test-Path -LiteralPath $reportFile) { Remove-Item -LiteralPath $reportFile }
    }
    $snapshotSource = Get-Content -LiteralPath 'scripts/data-snapshot.mjs' -Raw -Encoding UTF8
    $existingSnapshot = $null
    $previousAccountsHash = $null
    $previousCAHash = $null
    $existingApp = (Invoke-DockerChecked @composeArgs ps --quiet app)
    if ($existingApp) {
        # Runs against the old image too: the source uses only built-in Node modules.
        # Capture only row fingerprints; no password hashes, names or tokens are printed.
        $snapshotArgs = $composeArgs + @('exec', '--no-TTY', 'app', 'node', '--input-type=module')
        $existingSnapshot = (Invoke-DockerInput -InputText $snapshotSource -DockerArgs $snapshotArgs | ConvertFrom-Json)
        Invoke-DockerChecked @composeArgs cp 'app:/data/accounts.json' (Join-Path $privateDir 'accounts-before-upgrade.json')
        $previousAccountsHash = (Get-FileHash -LiteralPath (Join-Path $privateDir 'accounts-before-upgrade.json') -Algorithm SHA256).Hash
    }
    $existingGateway = (Invoke-DockerChecked @composeArgs ps --quiet gateway)
    if ($existingGateway) {
        Invoke-DockerChecked @composeArgs cp 'gateway:/data/caddy/pki/authorities/local/root.crt' (Join-Path $privateDir 'ca-before-upgrade.crt')
        $previousCAHash = (Get-FileHash -LiteralPath (Join-Path $privateDir 'ca-before-upgrade.crt') -Algorithm SHA256).Hash
    }
    Write-Host 'Building and starting isolated project safedrop-check on https://localhost:18443 ...'
    # Mounted Caddyfile changes require a new process even if its path is stable.
    # Recreating these verification containers preserves their named data volumes.
    Invoke-DockerChecked @composeBuildArgs up --build --force-recreate --detach --wait --wait-timeout 600
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
    if ($previousAccountsHash) { Assert-Condition ($accountsHash -eq $previousAccountsHash) 'Generated credentials changed during image upgrade.' }
    if ($previousCAHash) { Assert-Condition ($caHash -eq $previousCAHash) 'The gateway CA changed during image upgrade.' }
    $upgradeIdentity = [ordered]@{ accountsChecked = [bool]$previousAccountsHash; caChecked = [bool]$previousCAHash; stableAccounts = ($null -eq $previousAccountsHash -or $accountsHash -eq $previousAccountsHash); stableCA = ($null -eq $previousCAHash -or $caHash -eq $previousCAHash) }
    # Read the actual running binary, not just the Dockerfile or source lockfile.
    $gatewayBuildInfo = Invoke-DockerChecked @composeArgs exec --no-TTY gateway caddy build-info
    $gatewayJson = $gatewayBuildInfo | & node 'scripts/gateway-policy.mjs'
    if ($LASTEXITCODE -ne 0) { throw 'Running gateway dependency verification failed.' }
    $gatewayResult = $gatewayJson | ConvertFrom-Json
    Assert-Condition ([bool]$gatewayResult.ok) 'The running gateway does not contain the pinned security fixes.'
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-gateway.json'), ($gatewayResult | ConvertTo-Json -Depth 5), $utf8)
    Write-Host 'PASS running gateway Go/dependency versions; legacy go-jose is absent.'
    $appId = (Invoke-DockerChecked @composeArgs ps --quiet app).Trim()
    $gatewayId = (Invoke-DockerChecked @composeArgs ps --quiet gateway).Trim()
    $scannerId = (Invoke-DockerChecked @composeArgs ps --quiet scanner).Trim()
    $appInfo = @(Invoke-DockerChecked inspect $appId | ConvertFrom-Json)[0]
    $gatewayInfo = @(Invoke-DockerChecked inspect $gatewayId | ConvertFrom-Json)[0]
    $scannerInfo = @(Invoke-DockerChecked inspect $scannerId | ConvertFrom-Json)[0]
    # Bind the upstream fix assessment to every actual vendor binary/library and this image.
    $scannerProofSource = Get-Content -LiteralPath 'scripts/scanner-provenance.mjs' -Raw -Encoding UTF8
    $scannerProofArgs = $composeArgs + @('exec', '--no-TTY', 'scanner', '/nodejs/bin/node', '--input-type=module')
    $scannerProvenance = Invoke-DockerInput -InputText $scannerProofSource -DockerArgs $scannerProofArgs | ConvertFrom-Json
    Assert-Condition ([bool]$scannerProvenance.ok) 'Running scanner binaries differ from the pinned official vendor package.'
    $scannerProvenance | Add-Member -NotePropertyName imageId -NotePropertyValue $scannerInfo.Image
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-scanner-provenance.json'), ($scannerProvenance | ConvertTo-Json -Depth 6), $utf8)
    Write-Host 'PASS exact official scanner binaries, libraries and links; provenance bound to running image ID.'
    # Save only non-secret configuration so a failed check can be diagnosed.
    $runtimeEvidence = [ordered]@{ created = [DateTime]::UtcNow.ToString('o'); appUser = $appInfo.Config.User; appNetworks = @($appInfo.NetworkSettings.Networks.PSObject.Properties.Name); gatewayNetworks = @($gatewayInfo.NetworkSettings.Networks.PSObject.Properties.Name); gatewayRequestedPorts = $gatewayInfo.HostConfig.PortBindings; gatewayPublishedPorts = $gatewayInfo.NetworkSettings.Ports }
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-runtime.json'), ($runtimeEvidence | ConvertTo-Json -Depth 6), $utf8)
    Assert-Condition ($appInfo.Config.User -eq '10001:10001') 'The application is not running as UID/GID 10001.'
    Assert-Condition ($scannerInfo.Config.User -eq '65532:65532') 'The scanner is not running as UID/GID 65532.'
    foreach ($serviceInfo in @($appInfo, $gatewayInfo, $scannerInfo)) {
        Assert-Condition ([bool]$serviceInfo.HostConfig.ReadonlyRootfs) 'A container root filesystem is writable.'
        Assert-Condition ($serviceInfo.HostConfig.CapDrop -contains 'ALL') 'A container has not dropped all capabilities.'
        Assert-Condition (@($serviceInfo.HostConfig.SecurityOpt | Where-Object { $_ -match '^no-new-privileges(:true)?$' }).Count -gt 0) 'Privilege escalation is not disabled.'
        Assert-Condition ($serviceInfo.HostConfig.Memory -gt 0 -and $serviceInfo.HostConfig.NanoCpus -gt 0 -and $serviceInfo.HostConfig.PidsLimit -gt 0) 'Container resource limits are missing.'
    }
    $appPublished = @($appInfo.NetworkSettings.Ports.PSObject.Properties | Where-Object { $null -ne $_.Value })
    Assert-Condition ($appPublished.Count -eq 0) 'The application has a published host port.'
    $scannerPublished = @($scannerInfo.NetworkSettings.Ports.PSObject.Properties | Where-Object { $null -ne $_.Value })
    Assert-Condition ($scannerPublished.Count -eq 0) 'The scanner has a published host port.'
    $actualScannerNetworks = @($scannerInfo.NetworkSettings.Networks.PSObject.Properties.Name)
    Assert-Condition ($actualScannerNetworks.Count -eq 2 -and $actualScannerNetworks -contains $composeModel.networks.PSObject.Properties[$backendName].Value.name -and $actualScannerNetworks -contains $composeModel.networks.signatures.name) 'Unexpected scanner networks.'
    $scannerDataName = $composeModel.volumes.scanner_data.name
    $actualScannerMounts = @($scannerInfo.Mounts | Where-Object { $_.Type -ne 'tmpfs' })
    Assert-Condition ($actualScannerMounts.Count -eq 1 -and $actualScannerMounts[0].Type -eq 'volume' -and $actualScannerMounts[0].Name -eq $scannerDataName -and $actualScannerMounts[0].Destination -eq '/data') 'The scanner mounted business data or an unexpected volume.'
    Assert-Condition ($scannerInfo.HostConfig.Memory -eq 4GB -and $scannerInfo.HostConfig.Tmpfs.'/tmp' -eq 'size=1536m,noexec,nosuid,uid=65532,gid=65532,mode=0700') 'Scanner memory or temporary space bounds changed.'
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
    $profile = [ordered]@{ created = [DateTime]::UtcNow.ToString('o'); ok = $true; checks = @('Non-root application and scanner', 'Read-only roots', 'All capabilities dropped', 'Privilege escalation disabled', 'Memory/CPU/PID limits', 'Internal backend without published app ports', 'Separate gateway ingress network', 'Loopback-only gateway', 'Scanner has no published port or business/key mounts', 'Scanner has bounded memory/tmp and separate signature-update egress') }
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-profile.json'), ($profile | ConvertTo-Json -Depth 4), $utf8)
    # Exercise MFA in the actual final image using only a new /tmp fixture.
    # Existing admin/alice/bob credentials and MFA settings are never changed.
    $mfaSource = Get-Content -LiteralPath 'tests/container-mfa.mjs' -Raw -Encoding UTF8
    $mfaArgs = $composeArgs + @('exec', '--no-TTY', 'app', 'node', '--input-type=module')
    $expirySource = Get-Content -LiteralPath 'tests/container-delivery-expiry.mjs' -Raw -Encoding UTF8
    $expiryResult = Invoke-DockerInput -InputText $expirySource -DockerArgs $mfaArgs | ConvertFrom-Json
    Assert-Condition ([bool]$expiryResult.ok -and [bool]$expiryResult.realScanner -and [bool]$expiryResult.waitCancelled -and $expiryResult.databaseVersion -eq 7) 'Delivery expiry verification failed inside the final runtime.'
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-delivery-expiry.json'), ($expiryResult | ConvertTo-Json -Depth 5), $utf8)
    Write-Host 'PASS timed delivery, expiry cancellation, legacy grants, restart and encrypted restore in isolated temporary accounts.'
    # Real patched engine in the actual final images; only fresh /tmp accounts and samples.
    $scanSource = (Get-Content -LiteralPath 'tests/scan-samples.mjs' -Raw -Encoding UTF8) + "`n" + (Get-Content -LiteralPath 'tests/container-scan.mjs' -Raw -Encoding UTF8)
    $scanResult = Invoke-DockerInput -InputText $scanSource -DockerArgs $mfaArgs | ConvertFrom-Json
    Assert-Condition ([bool]$scanResult.ok -and [bool]$scanResult.malwareApi -and $scanResult.engine -match '^ClamAV 1\.5\.5/') 'Real scanner API verification failed inside the final runtime.'
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-scan.json'), ($scanResult | ConvertTo-Json -Depth 5), $utf8)
    Write-Host 'PASS real scanner, quarantine, archive limits, expiry, restart and encrypted restore in isolated temporary accounts.'
    $mfaResult = Invoke-DockerInput -InputText $mfaSource -DockerArgs $mfaArgs | ConvertFrom-Json
    Assert-Condition ([bool]$mfaResult.ok) 'Isolated MFA verification failed inside the final container image.'
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-mfa.json'), ($mfaResult | ConvertTo-Json -Depth 5), $utf8)
    $backupProbe = Get-Content -LiteralPath 'tests/container-backup.mjs' -Raw -Encoding UTF8
    $backupResult = Invoke-DockerInput -InputText $backupProbe -DockerArgs $mfaArgs | ConvertFrom-Json
    Assert-Condition ([bool]$backupResult.ok) 'Isolated encrypted backup verification failed inside the final runtime.'
    # Explicit initialization for this verification deployment. Existing keys are never replaced.
    # The CLI refuses a new key when encrypted copies exist but their key file is missing.
    $keyPresenceSource = "import {existsSync} from 'node:fs'; console.log(JSON.stringify({present:existsSync('/data/store.backup-keys')}));"
    $keyPresence = Invoke-DockerInput -InputText $keyPresenceSource -DockerArgs $mfaArgs | ConvertFrom-Json
    if ($keyPresence.present) {
        $backupKeyStatus = Invoke-DockerChecked @composeArgs exec --no-TTY app node build/scripts/maintenance.js keys-status --key-file /data/store.backup-keys --data-dir /data/store --backup-dir /data/store.backups | ConvertFrom-Json
    } else {
        $backupKeyStatus = Invoke-DockerChecked @composeArgs exec --no-TTY app node build/scripts/maintenance.js keys-init --key-file /data/store.backup-keys --data-dir /data/store --backup-dir /data/store.backups | ConvertFrom-Json
    }
    Assert-Condition ($backupKeyStatus.activeKeyId -match '^[0-9a-f-]{36}$') 'The independent backup key identifier is invalid.'
    $backupResult | Add-Member -NotePropertyName activeKeyId -NotePropertyValue $backupKeyStatus.activeKeyId
    $hostBackupKey = Join-Path $privateDir 'deployment.backup-keys'
    Invoke-DockerChecked @composeArgs cp 'app:/data/store.backup-keys' $hostBackupKey
    $backupKeyHash = (Get-FileHash -LiteralPath $hostBackupKey -Algorithm SHA256).Hash
    & node 'node_modules/tsx/dist/cli.mjs' 'tests/container-smoke.ts' seed $privateDir
    if ($LASTEXITCODE -ne 0) { throw 'HTTPS/WSS transfer checks failed before restart.' }
    # The host keeps an independent checkpoint and restores only into a fresh private directory.
    $maintenanceState = Get-Content -LiteralPath (Join-Path $privateDir 'state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Condition ($maintenanceState.backupId -match '^backup-[0-9a-f-]{36}$') 'Invalid backup identifier.'
    $backupPath = Join-Path $privateDir $maintenanceState.backupId
    Assert-Condition (-not (Test-Path -LiteralPath $backupPath)) 'The verification backup destination already exists.'
    Invoke-DockerChecked @composeArgs cp ("app:/data/store.backups/" + $maintenanceState.backupId) $backupPath
    $checkpointPath = Join-Path $privateDir 'maintenance-checkpoint.json'
    [IO.File]::WriteAllText($checkpointPath, ($maintenanceState.checkpoint | ConvertTo-Json), $utf8)
    & node 'node_modules/tsx/dist/cli.mjs' 'scripts/maintenance.ts' verify --source $backupPath --anchor $checkpointPath --key-file $hostBackupKey
    if ($LASTEXITCODE -ne 0) { throw 'Copied backup failed integrity or independent checkpoint verification.' }
    $restorePath = Join-Path $privateDir ('restore-' + [Guid]::NewGuid().ToString())
    & node 'node_modules/tsx/dist/cli.mjs' 'scripts/maintenance.ts' restore --source $backupPath --target $restorePath --anchor $checkpointPath --key-file $hostBackupKey
    if ($LASTEXITCODE -ne 0) { throw 'Isolated restore failed. Existing verification data remains unchanged.' }
    Write-Host 'Restarting the verification containers while retaining their data volumes ...'
    Invoke-DockerChecked @composeArgs restart app gateway
    & node 'node_modules/tsx/dist/cli.mjs' 'tests/container-smoke.ts' resume $privateDir
    if ($LASTEXITCODE -ne 0) { throw 'Persistence or resume checks failed after restart.' }
    Invoke-DockerChecked @composeArgs cp 'app:/data/accounts.json' (Join-Path $privateDir 'accounts-after.json')
    Invoke-DockerChecked @composeArgs cp 'gateway:/data/caddy/pki/authorities/local/root.crt' (Join-Path $privateDir 'ca-after.crt')
    Assert-Condition ((Get-FileHash -LiteralPath (Join-Path $privateDir 'accounts-after.json') -Algorithm SHA256).Hash -eq $accountsHash) 'Generated credentials changed after restart.'
    Assert-Condition ((Get-FileHash -LiteralPath (Join-Path $privateDir 'ca-after.crt') -Algorithm SHA256).Hash -eq $caHash) 'The gateway CA changed after restart.'
    $hostBackupKeyAfter = Join-Path $privateDir 'deployment-after.backup-keys'
    Invoke-DockerChecked @composeArgs cp 'app:/data/store.backup-keys' $hostBackupKeyAfter
    Assert-Condition ((Get-FileHash -LiteralPath $hostBackupKeyAfter -Algorithm SHA256).Hash -eq $backupKeyHash) 'The independent backup key file changed after restart.'
    $backupResult | Add-Member -NotePropertyName stableKeyRing -NotePropertyValue $true
    [IO.File]::WriteAllText((Join-Path $projectRoot 'reports/container-backup.json'), ($backupResult | ConvertTo-Json -Depth 5), $utf8)
    $summary = [ordered]@{ version = 11; created = [DateTime]::UtcNow.ToString('o'); ok = $true; project = 'safedrop-check'; origin = 'https://localhost:18443'; existingData = $existingData; upgradeIdentity = $upgradeIdentity; gateway = $gatewayResult; profile = $profile; before = (Get-Content -LiteralPath 'reports/container-seed.json' -Raw -Encoding UTF8 | ConvertFrom-Json); after = (Get-Content -LiteralPath 'reports/container-resume.json' -Raw -Encoding UTF8 | ConvertFrom-Json); stableAccounts = $true; stableCA = $true; backup = [ordered]@{ verified = $true; isolatedRestore = $true; independentCheckpoint = $true; encrypted = $true }; mfa = $mfaResult; backupEncryption = $backupResult; scanning = $scanResult; scannerProvenance = $scannerProvenance; scannerBuildInput = $scannerBuildInput; deliveryExpiry = $expiryResult }
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
