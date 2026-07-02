# ServerManager

跨平台 Web 服务器管理程序第一阶段实现，聚焦浏览器在线 SSH 与 RDP 连接。

## 当前能力

- Go 后端单进程服务，内嵌 NewAPI 风格静态管理界面。
- SSH：浏览器 WebSocket 到服务端 SSH PTY，支持密码、私钥、私钥 passphrase。
- RDP：浏览器 Guacamole tunnel 到 `guacd`，服务端注入 RDP 凭据、录屏目录、文件传输参数。
- 数据：本地 JSON 文件存储，模型已覆盖服务器、凭据、连接会话、审计日志。
- 安全：凭据字段 AES-GCM 加密保存，API 响应不会返回明文凭据。

## 启动

```powershell
go run ./cmd/servermanager
```

默认监听 `http://127.0.0.1:8080`，数据目录为 `data/`。

建议设置固定主密钥：

```powershell
$env:SERVERMANAGER_MASTER_KEY="change-this-to-a-long-random-secret"
go run ./cmd/servermanager
```

## RDP / guacd

RDP 依赖 Apache Guacamole 的 `guacd`。服务启动时会按以下顺序寻找：

1. 环境变量 `SERVERMANAGER_GUACD_HOST` / `SERVERMANAGER_GUACD_PORT` 指向的外部 `guacd`。
2. 当前工作目录下 `runtime/guacd/<goos>/guacd` 或 `guacd.exe`。

原生捆绑构建产物请放入：

- Linux: `runtime/guacd/linux/guacd`
- Windows: `runtime/guacd/windows/guacd.exe`

录屏默认保存到 `data/recordings/{session_id}/`。

## API 摘要

- `GET /api/bootstrap` 获取页面初始化数据。
- `POST /api/servers` 创建服务器。
- `POST /api/credentials` 创建凭据。
- `POST /api/connections/ssh` 创建 SSH 会话。
- `GET /api/connections/ssh/{session_id}/ws` 连接 SSH WebSocket。
- `POST /api/connections/rdp` 创建 RDP 会话。
- `GET /api/connections/rdp/{session_id}/tunnel` 连接 Guacamole WebSocket tunnel。
- `POST /api/connections/{session_id}/close` 关闭会话。

## 前端说明

静态前端在 `cmd/servermanager/static`。RDP 页面需要加载 `guacamole-common-js`，当前默认尝试 `/vendor/guacamole-common.min.js`；若未放置该文件，页面会显示明确提示。