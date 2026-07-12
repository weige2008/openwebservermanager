# openwebservermanager

openwebservermanager 是一个自托管的网页端服务器管理控制台，用于在浏览器中统一管理服务器资产、连接账号、在线 SSH 终端、在线 RDP 桌面、文件传输、会话录屏与审计日志。

默认文档语言为简体中文。其它语言版本：

- [English](docs/i18n/README.en.md)
- [繁體中文](docs/i18n/README.zh-TW.md)
- [Français](docs/i18n/README.fr.md)
- [Русский](docs/i18n/README.ru.md)
- [日本語](docs/i18n/README.ja.md)
- [Tiếng Việt](docs/i18n/README.vi.md)

部署指南：

- [简体中文](DEPLOYMENT.md)
- [English](docs/i18n/DEPLOYMENT.en.md)
- [繁體中文](docs/i18n/DEPLOYMENT.zh-TW.md)
- [Français](docs/i18n/DEPLOYMENT.fr.md)
- [Русский](docs/i18n/DEPLOYMENT.ru.md)
- [日本語](docs/i18n/DEPLOYMENT.ja.md)
- [Tiếng Việt](docs/i18n/DEPLOYMENT.vi.md)

## 功能特性

- Go 后端内嵌静态前端，单二进制即可运行。
- 前端技术栈对齐 NewAPI 新版 UI 方案：Rsbuild、React 19、TypeScript、Tailwind CSS v4、TanStack Router、TanStack Query、TanStack Table、Base UI、i18next、Zustand。
- 首次启动创建管理员密码，登录后才能查看服务器资产、连接账号、会话和审计数据。
- SSH：WebSocket 到 SSH PTY 桥接，支持密码、私钥和私钥 passphrase，并提供受授权策略控制的 SFTP 文件浏览、上传、下载、删除与审计日志。
- Agent 网关：远端节点主动连接管理端，通过经过鉴权和审计的双向 TCP 中继访问内网 SSH/SFTP 资产，带网关的会话不会静默回退为直连。
- RDP：通过 Guacamole WebSocket tunnel 连接 `guacd`，真实凭据只在服务端使用。
- 本地 JSON 数据存储，凭据敏感字段使用 AES-GCM 加密。
- RDP 会话录屏索引与管理员下载入口。
- GitHub Actions 自动构建 Linux、Windows、macOS 发布包。

## 本地运行

```powershell
go run ./cmd/openwebservermanager
```

默认监听地址为 `http://127.0.0.1:23876`，默认数据目录为 `data/`。

真实使用前建议设置稳定的主密钥：

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

首次运行时打开 `/login` 创建管理员密码。管理员密码以 bcrypt 哈希保存；SSH/RDP 明文凭据提交后会在服务端加密存储，API 响应不会返回明文凭据。

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `OPENWEBSERVERMANAGER_ADDR` | `127.0.0.1:23876` | HTTP 监听地址 |
| `OPENWEBSERVERMANAGER_DATA_DIR` | `data` | 数据、密钥、录屏和文件传输目录 |
| `OPENWEBSERVERMANAGER_MASTER_KEY` | 自动生成 `data/master.key` | 凭据加密主密钥来源 |
| `OPENWEBSERVERMANAGER_GUACD_HOST` | 自动查找内置运行时 | 外部 guacd 主机 |
| `OPENWEBSERVERMANAGER_GUACD_PORT` | `4822` | guacd 端口 |
| `OPENWEBSERVERMANAGER_GUACD_RUNTIME` | `runtime/guacd` | 内置 guacd 运行时根目录 |
| `OPENWEBSERVERMANAGER_SHARED_DIR_MODE` | `0770` | guacd 共享录屏/驱动目录权限 |
| `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS` | `false` | 是否信任 `X-Forwarded-*` 和 `X-Real-IP` |
| `OPENWEBSERVERMANAGER_VERSION` | 构建版本 | 前端公开配置显示的版本 |
| `OPENWEBSERVERMANAGER_GITHUB_URL` | 项目仓库地址 | UI 中展示的 GitHub 链接 |
| `OPENWEBSERVERMANAGER_COPYRIGHT` | weige2008 copyright | UI 中展示的版权信息 |

## RDP 与 guacd

RDP 连接依赖 Apache Guacamole `guacd`。

查找顺序：

1. 如果设置了 `OPENWEBSERVERMANAGER_GUACD_HOST` 和 `OPENWEBSERVERMANAGER_GUACD_PORT`，优先连接外部 guacd。
2. 否则尝试使用 `runtime/guacd/<goos>/bin/guacd` 或 `guacd.exe`，同时兼容旧的运行时根目录布局。

预期内置路径：

- Linux amd64：`runtime/guacd/linux/bin/guacd`
- Windows amd64：`runtime/guacd/windows/bin/guacd.exe`

官方 Linux amd64 和 Windows amd64 Release 包已内置通过 RDP/VNC 握手测试的运行时。其他架构可通过 `OPENWEBSERVERMANAGER_GUACD_HOST` 和 `OPENWEBSERVERMANAGER_GUACD_PORT` 使用外部 guacd。

RDP 录屏保存到 `data/recordings/{session_id}/`。文件传输 drive 目录保存到 `data/drives/{session_id}/`。

## 安全说明

- 业务 API 需要管理员登录会话。
- 非安全 API 方法在存在 `Origin` 头时会拒绝跨源请求。
- 会话 Cookie 使用 `HttpOnly`、`SameSite=Lax`，HTTPS 下启用 `Secure`。
- 登录失败会按用户名和客户端 IP 限流。
- SSH 主机密钥保存到 `data/known_hosts`；未知主机首次使用时接受，后续不匹配会拒绝。
- WebSocket 升级会校验版本、key、mask、帧大小和不支持的分片。
- 除非设置 `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS=1`，否则忽略 `X-Forwarded-*` 头。

## 开发

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
```

生产前端构建会写入 `cmd/openwebservermanager/static/`，并由 Go 后端内嵌。

```powershell
npm --prefix frontend run build
go test ./...
```

## 部署

完整部署说明见 [DEPLOYMENT.md](DEPLOYMENT.md)。

快速部署到默认测试服务器：

```powershell
.\scripts\deploy.ps1
```

默认脚本部署到 `/opt/openwebservermanager`，在服务器上构建前后端，并让 systemd 服务监听 `23876` 端口。

## 发布

项目版本记录在 `VERSION`。每次更新递增 patch、minor 或 major 版本，然后推送对应语义化版本 tag 触发 GitHub Actions 发布：

```powershell
git tag v1.0.11
git push origin v1.0.11
```

工作流构建：

- `linux-amd64`
- `linux-arm64`
- `windows-amd64`
- `windows-arm64`
- `darwin-amd64`
- `darwin-arm64`

发布包包含 `openwebservermanager`、`openwebservermanager-agent` 二进制、默认中文文档、多语言文档、`VERSION` 和 `runtime/` 目录。
