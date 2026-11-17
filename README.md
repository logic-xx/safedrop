# SafeDrop

安全文件传输与审计平台。

SafeDrop 将加密传输、身份验证、断点续传和可校验操作记录放在同一个工作空间。采用 Vue 3、TypeScript、Node.js 和 SQLite，支持本地运行及 Docker Compose 部署。

![SafeDrop 登录界面](docs/screenshots/login.jpg)

## 功能

- **安全通道**：HTTPS/WSS，严格校验证书，持续连接与心跳检测。
- **可恢复传输**：二进制分块、完整文件 SHA-256 校验、上传与下载续传。
- **多任务处理**：同时上传和下载多个文件，独立进度与暂停控制。
- **账号策略**：默认邀请注册、限时单次邀请、关闭自助注册、修改口令和管理员停用。
- **身份与权限**：口令及 P-256 公钥认证、用户文件隔离、会话查看与撤销。
- **资源控制**：按账号汇总的带宽限制、消息大小与并发上限、文件存储配额。
- **可验证记录**：安全事件时间线、审计哈希链、独立检查点及离线校验工具。
- **安全验证**：独立运行 TLS/WSS 集成测试，生成 HTML 与 JSON 报告。

## 本地运行

需要 Node.js 24.14+（24.x）、npm 和 OpenSSL。

```sh
npm ci
npm run setup
npm run build
npm start
```

入口为 `https://localhost:8443`。初始化生成的账号资料位于 `.local/accounts.json`，本地 CA 公共证书位于 `.local/tls/ca.crt`。请核对并信任本地 CA 后连接；不要关闭证书验证。

账号资料、私钥和运行数据均不纳入源码仓库。

## 文档

- [运行与部署](docs/运行与验收.md)：启动、账号初始化、文件传输、Docker Compose 与公网 HTTPS 配置。
- [协议与安全设计](docs/协议与安全设计.md)：报文格式、认证、续传、限速、审计和信任边界。
- [验证记录](docs/验证记录.md)：已完成的容器检查、原始报告摘要及验证范围。
- [浏览器验收清单](docs/浏览器验收清单.md)：公钥登录、多任务传输和原生文件恢复的操作步骤。
- [开发路线图](docs/开发路线图.md)：20 项任务的当前状态、执行顺序，以及指定用户发送和公网展示的范围。

## 验证

```sh
npm test
npm run security:report
```

报告输出到 `reports/latest.html` 和 `reports/latest.json`。测试使用独立的临时账号与数据，生产界面只读取报告，不提供远程触发测试的接口。

管理员导出的审计日志可以对照独立保存的检查点校验：

```sh
npm run audit:verify -- audit.json checkpoint.json
```

## 部署

本地部署使用 `compose.yaml`，公网部署使用 `compose.public.yaml`。公网入口由 Caddy 管理 Let's Encrypt 证书，应用服务仅位于容器内部网络。完整前提和验证状态见运行文档。

Windows 下可在已启动 Docker Desktop 的普通 PowerShell 中运行独立容器验收：

```powershell
.\scripts\verify-container.ps1
```

工具使用单独的 `safedrop-check` 项目、数据卷及 `18443` 本机端口，检查容器权限、升级前后原数据保留、账号注册与撤销、HTTPS/WSS 传输、重启后的文件与续传位置，并输出 `reports/container-latest.json`。工具不会修改系统证书信任；凭据只存放在忽略提交的 `.local/container-check/` 中。

当前版本为 0.1.0，已通过独立 Linux 容器的 HTTPS/WSS、权限与网络隔离及重启恢复检查，含单条 HSTS 策略验证；本机 Edge 的 9 项浏览器验收也已通过。邀请、改密和停用最小流程已实现，新增验收状态见验证记录。公开部署前还需完善账号恢复、必要的全局存储与维护保障，以及真实公网证书和访问验证。安全验证结果仅覆盖列出的场景，不等同于全面安全审计。
