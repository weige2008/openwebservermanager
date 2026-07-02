# ServerManager

跨平台 Web 服务器管理程序，第一阶段聚焦浏览器在线 SSH 与 RDP 连接。

## 当前能力

- Go 后端单进程服务，内嵌 NewAPI 新版风格的静态管理界面。
- 公开首页与登录页；服务器、凭据、会话、审计日志必须登录后查看。
- SSH：浏览器 WebSocket 到服务端 SSH PTY，支持密码、私钥、私钥 passphrase。
- RDP：浏览器 Guacamole tunnel 到 `guacd`，服务端注入 RDP 凭据、录屏目录、文件传输参数。
- 数据：本地 JSON 文件存储，模型覆盖服务器、凭据、连接会话、审计日志。
- 安全：凭据字段 AES-GCM 加密保存，API 响应不返回明文凭据。

## 启动

```powershell
go run ./cmd/servermanager
```

默认监听 `http://127.0.0.1:8080`，数据目录为 `data/`。

建议设置固定主密钥和管理员账号：

```powershell
$env:SERVERMANAGER_MASTER_KEY="change-this-to-a-long-random-secret"
$env:SERVERMANAGER_ADMIN_USER="admin"
$env:SERVERMANAGER_ADMIN_PASSWORD="change-this-password"
go run ./cmd/servermanager
```

如果未设置管理员环境变量，MVP 默认账号为 `admin / admin123`，生产环境必须修改。

## RDP / guacd

RDP 依赖 Apache Guacamole 的 `guacd`。服务启动时会按以下顺序寻找：

1. 环境变量 `SERVERMANAGER_GUACD_HOST` / `SERVERMANAGER_GUACD_PORT` 指向的外部 `guacd`。
2. 当前工作目录中的 `runtime/guacd/<goos>/guacd` 或 `guacd.exe`。

原生捆绑构建产物请放入：

- Linux: `runtime/guacd/linux/guacd`
- Windows: `runtime/guacd/windows/guacd.exe`

录屏默认保存到 `data/recordings/{session_id}/`。

## API 摘要

- `POST /api/auth/login` 登录并设置 HttpOnly Cookie。
- `POST /api/auth/logout` 退出登录。
- `GET /api/auth/me` 获取当前登录用户。
- `GET /api/bootstrap` 获取登录后的页面初始化数据。
- `POST /api/servers` 创建服务器。
- `POST /api/credentials` 创建凭据。
- `POST /api/connections/ssh` 创建 SSH 会话。
- `GET /api/connections/ssh/{session_id}/ws` 连接 SSH WebSocket。
- `POST /api/connections/rdp` 创建 RDP 会话。
- `GET /api/connections/rdp/{session_id}/tunnel` 连接 Guacamole WebSocket tunnel。
- `POST /api/connections/{session_id}/close` 关闭会话。

除认证接口外，业务 API 都需要登录。

## 部署

```powershell
.\scripts\deploy.ps1
```

默认部署到 `/opt/servermanager` 并监听 `0.0.0.0:8080`。
