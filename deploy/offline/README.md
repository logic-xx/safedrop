# SafeDrop 离线镜像导入与启动

分发目录包含 `images.tar`、`compose.yaml`、`Caddyfile`、`image-manifest.json`、`SHA256SUMS.txt` 和本说明。三张镜像面向 Linux x86-64。Windows 使用 Docker Desktop 的 Linux 引擎和 Docker Compose v2。扫描器内存上限为 4 GiB，请给 Docker 和其他服务预留额外空间。首次启动会创建本包专用的新数据卷、CA 和随机账号。

## 校验与导入

打包时另存了外层 `.tar.gz.sha256`。先从可信途径核对该文件，再用 `Get-FileHash -Algorithm SHA256` 对照压缩包的摘要。将 `.tar.gz` 解到新目录，在该目录打开普通 PowerShell，执行以下命令。校验结束时会显示 `SHA-256 OK`。

```powershell
$verified = @{}
Get-Content -LiteralPath '.\SHA256SUMS.txt' -ErrorAction Stop | ForEach-Object {
    if ($_ -notmatch '^([a-f0-9]{64})  (images\.tar|compose\.yaml|Caddyfile|image-manifest\.json|README\.md)$') { throw 'Invalid checksum line' }
    $expected = $Matches[1]
    $file = $Matches[2]
    if ($verified.ContainsKey($file)) { throw "Duplicate checksum for $file" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file -ErrorAction Stop).Hash -ne $expected) { throw "SHA-256 mismatch for $file" }
    $verified[$file] = $true
}
if ($verified.Count -ne 5) { throw 'Incomplete SHA-256 manifest' }
'SHA-256 OK'
docker load --input .\images.tar
if ($LASTEXITCODE -ne 0) { throw 'Docker image import failed' }
```

`image-manifest.json` 记录三张镜像的标签、实际 ID、来源和内置签名截止时间。校验和用于核对收到的字节，可信来源需要由分发者另行确认。 [Docker 镜像导入说明](https://docs.docker.com/reference/cli/docker/image/load/)

## 启动与登录

确认本机 `8443` 端口空闲，使用本包目录下的配置启动。若已有 SafeDrop 实例，可以在当前 PowerShell 设置 `$env:SAFEDROP_OFFLINE_PORT='18446'`，再用该端口访问和继续本例。对同一部署保持项目名与端口设置一致。

```powershell
docker compose -p safedrop-offline-prepared up -d --no-build --pull never --wait --wait-timeout 360
docker compose -p safedrop-offline-prepared ps
New-Item -ItemType Directory -Path '.local' -Force | Out-Null
docker compose -p safedrop-offline-prepared cp gateway:/data/caddy/pki/authorities/local/root.crt .local/ca.crt
docker compose -p safedrop-offline-prepared cp app:/data/accounts.json .local/accounts.json
Get-Content -Raw -LiteralPath '.local/accounts.json'
```

核对本次网关生成的公开 CA 后，将 `.local/ca.crt` 安装到 Windows 当前用户的受信任根证书存储，重新打开浏览器，访问 `https://localhost:8443`（或所选端口）。账号口令仅在本地私下查看。`alice` 和 `bob` 可验证上传、扫描、交付与下载，`admin` 可检查维护状态。上传无害小文件，等候「扫描通过」，下载到另一文件名并用 SHA-256 对比。使用 `docker compose -p safedrop-offline-prepared stop` 停止服务并保留本包实例的数据。

## 离线签名的有效期

离线扫描器随镜像提供在打包时经 FreshClam 更新和测试的官方签名。容器启动时直接运行 ClamD，部署的扫描器仅连接隔离后端网络。应用照常检查签名发布时间，超过 72 小时后新扫描无法通过，需取得带新签名的镜像包。请优先在清单所列截止时间前导入并完成传输验证。应用仍按自己的规则检查已存在的扫描结果时效。

历史版本 12 的验收对应原镜像。离线扫描器在原镜像上加入签名与启动配置，拥有新的镜像 ID，原 CI 扫描结论不外推。源码、组件许可证定位和历史证据见分发清单及 SafeDrop 仓库。 [SafeDrop 仓库](https://github.com/logic-xx/safedrop)
