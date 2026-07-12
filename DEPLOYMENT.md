# openwebservermanager 部署指南

默认语言为简体中文。其它语言：

- [English](docs/i18n/DEPLOYMENT.en.md)
- [繁體中文](docs/i18n/DEPLOYMENT.zh-TW.md)
- [Français](docs/i18n/DEPLOYMENT.fr.md)
- [Русский](docs/i18n/DEPLOYMENT.ru.md)
- [日本語](docs/i18n/DEPLOYMENT.ja.md)
- [Tiếng Việt](docs/i18n/DEPLOYMENT.vi.md)

## 目标

本指南说明如何把 openwebservermanager 部署到 Linux/Windows 环境，并让浏览器访问在线 SSH 与 RDP 工作区。

默认端口为 `23876`。数据默认放在 `data/` 或服务器部署目录的 `data/` 下。

## 部署前准备

### 通用要求

- Go 1.25 或更新版本。
- Node.js 22 或更新版本，用于构建前端。
- 一个稳定的 `OPENWEBSERVERMANAGER_MASTER_KEY`，用于加密 SSH/RDP 凭据。
- 如果需要 RDP：可用的 Apache Guacamole `guacd` 和 FreeRDP 运行环境。

### Linux 建议

- 使用 systemd 管理服务。
- 生产环境建议使用反向代理提供 HTTPS。
- 如果使用本机 guacd，确保 openwebservermanager 与 guacd 对录屏/drive 目录有共同读写权限。

### Windows 建议

- 可直接运行发布包中的 `.exe`。
- 生产运行可用 NSSM、Windows Service Wrapper 或计划任务守护进程。
- RDP 需要可用的 Windows 版 guacd 运行时，路径为 `runtime/guacd/windows/guacd.exe`，或配置外部 guacd。

## 快速部署到默认测试服务器

仓库内置 PowerShell 部署脚本：

```powershell
.\scripts\deploy.ps1
```

默认行为：

- 打包当前 Git HEAD。
- 上传到服务器。
- 解包到 `/opt/openwebservermanager/src`。
- 执行 `npm ci`、前端构建、`go build`。
- 写入 systemd 服务 `openwebservermanager.service`。
- 监听 `0.0.0.0:23876`。

可选参数：

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## 手动 Linux 部署

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

创建数据目录：

```bash
sudo mkdir -p /opt/openwebservermanager/data/recordings /opt/openwebservermanager/data/drives
sudo chmod 2770 /opt/openwebservermanager/data /opt/openwebservermanager/data/recordings /opt/openwebservermanager/data/drives
```

示例 systemd：

```ini
[Unit]
Description=openwebservermanager web server management console
After=network-online.target guacd.service
Wants=network-online.target guacd.service

[Service]
Type=simple
WorkingDirectory=/opt/openwebservermanager/src
Environment=OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
Environment=OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
Environment=OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
Environment=OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
Environment=OPENWEBSERVERMANAGER_GUACD_PORT=4822
ExecStart=/opt/openwebservermanager/bin/openwebservermanager
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openwebservermanager
sudo systemctl status openwebservermanager
```

## 使用发布包

从 GitHub Release 下载对应系统架构的压缩包：

- Linux：`openwebservermanager-<version>-linux-amd64.tar.gz`
- Windows：`openwebservermanager-<version>-windows-amd64.zip`
- macOS：`openwebservermanager-<version>-darwin-arm64.tar.gz`

解压后运行：

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876 \
OPENWEBSERVERMANAGER_DATA_DIR=./data \
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret \
./openwebservermanager
```

Windows PowerShell：

```powershell
$env:OPENWEBSERVERMANAGER_ADDR = "0.0.0.0:23876"
$env:OPENWEBSERVERMANAGER_DATA_DIR = ".\data"
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
.\openwebservermanager.exe
```

## 反向代理

生产环境建议启用 HTTPS，并代理 WebSocket。

Nginx 示例：

```nginx
server {
  listen 443 ssl;
  server_name example.com;

  location / {
    proxy_pass http://127.0.0.1:23876;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
```

如果需要读取反向代理 IP 头，显式设置：

```bash
OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS=1
```

## Agent 网关

在管理后台的“安全网关”中创建 Agent 网关并生成一次性显示的注册令牌，然后在能够访问目标内网资产的节点运行：

```bash
OPENWEBSERVERMANAGER_AGENT_TOKEN='gateway_id.registration_secret' \
./openwebservermanager-agent -server https://manager.example.com -name edge-office-1
```

也可以使用 `OPENWEBSERVERMANAGER_AGENT_SERVER`、`OPENWEBSERVERMANAGER_AGENT_TOKEN`、`OPENWEBSERVERMANAGER_AGENT_NAME` 和 `OPENWEBSERVERMANAGER_AGENT_WORKERS` 环境变量。Agent 只需要主动访问管理端，不需要开放入站端口；注册令牌应按密码管理，不要写入日志或公开脚本。

为资产选择包含该 Agent 的网关分组后，SSH/SFTP 会通过经过鉴权和审计的双向 TCP 中继访问目标。网关不可用时连接会失败，不会静默回退为管理端直连。

如果管理端位于 Nginx 后面，`/api/agent/` 还需要禁用请求和响应缓冲，并放宽长连接超时：

```nginx
location /api/agent/ {
  proxy_pass http://127.0.0.1:23876;
  proxy_http_version 1.1;
  proxy_buffering off;
  proxy_request_buffering off;
  proxy_read_timeout 1h;
  proxy_send_timeout 1h;
}
```

## guacd 配置

RDP 需要 guacd。推荐优先使用系统服务：

```bash
sudo systemctl enable --now guacd
```

然后配置：

```bash
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

Linux amd64 和 Windows amd64 Release 包默认包含内置运行时：

- Linux：`runtime/guacd/linux/bin/guacd`
- Windows：`runtime/guacd/windows/bin/guacd.exe`

其他架构或自行构建的精简包可继续配置外部 guacd。Windows 内置运行时基于 Cygwin POSIX 兼容层，所需 DLL 已随 Release 一并发布，不需要单独安装 Cygwin。

## 首次初始化

部署后访问：

```text
http://<server-ip>:23876/login
```

如果数据库中还没有管理员，会进入首次初始化流程。创建管理员密码后才能进入后台控制台。

## 验证

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
```

前端和后端完整检查：

```bash
npm --prefix frontend run build
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```

## 常见问题

### 页面打不开

- 确认服务监听端口：`systemctl status openwebservermanager`。
- 确认防火墙或云安全组放行 `23876`。
- 如果通过反向代理访问，确认 WebSocket upgrade 头已配置。

### RDP 无法连接

- 确认 `guacd` 正在运行。
- 确认 `OPENWEBSERVERMANAGER_GUACD_HOST` 与端口正确。
- 确认目标 Windows 服务器允许 RDP 登录。

### 凭据无法解密

- 不要更换已使用过的 `OPENWEBSERVERMANAGER_MASTER_KEY`。
- 如果使用自动生成的 `data/master.key`，迁移时必须同步该文件。

### 录屏或文件传输失败

- 检查 `data/recordings` 和 `data/drives` 权限。
- 如果 guacd 以独立用户运行，确保它和 openwebservermanager 服务用户共享同一用户组。
