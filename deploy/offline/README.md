# SafeDrop 预构建镜像验收

分发目录包含 `images.tar`、`compose.yaml`、`compose.no-signature-network.yaml`、`Caddyfile`、`image-manifest.json`、`SHA256SUMS.txt` 和本说明。三张镜像面向 Linux x86-64。Windows 使用 Docker Desktop 的 Linux 引擎和 Docker Compose v2。扫描器内存上限为 4 GiB，请给 Docker 和其他服务预留额外空间。首次启动会创建本包专用的新数据卷、CA 和随机账号。

## 从公开 GHCR 免构建启动

从课程源码根目录打开 PowerShell。下列命令用 `deploy/offline/ghcr.env` 固定三张 Linux x86-64 镜像的摘要。公开镜像可匿名拉取。端口 8443 已占用时，先设置 `$env:SAFEDROP_OFFLINE_PORT='18446'`。

```powershell
$options = @('--env-file', 'deploy/offline/ghcr.env', '-f', 'deploy/offline/compose.yaml', '-p', 'safedrop-ghcr-review')
docker compose @options pull --policy always
if ($LASTEXITCODE -ne 0) { throw 'GHCR 镜像拉取失败' }
docker compose @options up -d --no-build --pull never --wait --wait-timeout 600
if ($LASTEXITCODE -ne 0) { throw 'SafeDrop 启动失败' }
docker compose @options ps
$reviewDir = '.local/ghcr-review'
New-Item -ItemType Directory -Force $reviewDir | Out-Null
docker compose @options cp gateway:/data/caddy/pki/authorities/local/root.crt "$reviewDir/ca.crt"
docker compose @options cp app:/data/accounts.json "$reviewDir/accounts.json"
```

核对并信任本次实例的公开 CA，再访问 `https://localhost:8443`（或所选端口）。私下查看本次生成的账号。结束时运行 `docker compose @options stop`，数据卷仍保留。签名更新要求见下文。

## 校验与导入

打包时另存了外层 `.tar.gz.sha256`。先从可信途径核对该文件，再用 `Get-FileHash -Algorithm SHA256` 对照压缩包的摘要。将 `.tar.gz` 解到新目录，在该目录打开普通 PowerShell，执行以下命令。校验结束时会显示 `SHA-256 OK`。

```powershell
$verified = @{}
Get-Content -LiteralPath '.\SHA256SUMS.txt' -ErrorAction Stop | ForEach-Object {
    if ($_ -notmatch '^([a-f0-9]{64})  (images\.tar|compose\.yaml|compose\.no-signature-network\.yaml|Caddyfile|image-manifest\.json|README\.md)$') { throw 'Invalid checksum line' }
    $expected = $Matches[1]
    $file = $Matches[2]
    if ($verified.ContainsKey($file)) { throw "Duplicate checksum for $file" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file -ErrorAction Stop).Hash -ne $expected) { throw "SHA-256 mismatch for $file" }
    $verified[$file] = $true
}
if ($verified.Count -ne 6) { throw 'Incomplete SHA-256 manifest' }
'SHA-256 OK'
docker load --input .\images.tar
if ($LASTEXITCODE -ne 0) { throw 'Docker image import failed' }
```

`image-manifest.json` 记录三张镜像的标签、来源、实际 ID 和归档摘要。OCI 归档另列索引或目标摘要及 Linux amd64 清单摘要。经典镜像存储的本地 ID 对应配置摘要，containerd 镜像存储的本地 ID 对应清单或索引。校验和用于核对收到的字节，可信来源由分发者另行确认。 [Docker 镜像导入说明](https://docs.docker.com/reference/cli/docker/image/load/)

## 启动与登录

确认本机 `8443` 端口空闲，使用本包目录下的配置启动。若已有 SafeDrop 实例，可以在当前 PowerShell 设置 `$env:SAFEDROP_OFFLINE_PORT='18446'`，再用该端口访问和继续本例。对同一部署保持项目名与端口设置一致。

```powershell
docker compose -p safedrop-offline-prepared up -d --no-build --pull never --wait --wait-timeout 600
docker compose -p safedrop-offline-prepared ps
New-Item -ItemType Directory -Path '.local' -Force | Out-Null
docker compose -p safedrop-offline-prepared cp gateway:/data/caddy/pki/authorities/local/root.crt .local/ca.crt
docker compose -p safedrop-offline-prepared cp app:/data/accounts.json .local/accounts.json
Get-Content -Raw -LiteralPath '.local/accounts.json'
```

核对本次网关生成的公开 CA 后，将 `.local/ca.crt` 安装到 Windows 当前用户的受信任根证书存储，重新打开浏览器，访问 `https://localhost:8443`（或所选端口）。账号口令仅在本地私下查看。`alice` 和 `bob` 可验证上传、扫描、交付与下载，`admin` 可检查维护状态。上传无害小文件，等候「扫描通过」，下载到另一文件名并用 SHA-256 对比。使用 `docker compose -p safedrop-offline-prepared stop` 停止服务并保留本包实例的数据。

## 验收当天更新签名

镜像导入可在断网时完成。正常启动时扫描器沿用 FreshClam，通过专用网络从 ClamAV 官方服务更新签名，把结果保存到独立签名卷，并定期检查更新。签名年龄从官方发布时间起算，默认上限为 72 小时。等待无害文件显示「扫描通过」后再下载。更新连接失败时可用 `docker compose -p safedrop-offline-prepared logs scanner` 排查。

完全断网时，需要从联网环境取得仍有效的官方签名并导入本次评阅实例的专用签名卷。过期种子可用于检查拒绝路径。用独立项目名和 `-f compose.yaml -f compose.no-signature-network.yaml` 验证时，扫描器外联网络也标记为内部网络。文件可上传，签名过期时状态为「扫描未完成」，应用拒绝下载和交付。恢复更新后由文件所有者重试扫描。

分发清单分别记录本包的联网更新、断网拒绝和传输结果，以及历史版本 12 证据对应的原镜像。 [SafeDrop 仓库](https://github.com/logic-xx/safedrop)
