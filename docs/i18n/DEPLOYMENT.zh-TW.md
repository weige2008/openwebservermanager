# openwebservermanager 部署指南

預設語言：[简体中文](../../DEPLOYMENT.md)

本指南說明如何在 Linux 或 Windows 部署 openwebservermanager，並提供瀏覽器 SSH/RDP 工作區。

預設端口：`23876`。

## 需求

- Go 1.25 或更新。
- Node.js 22 或更新，用於建置前端。
- 穩定的 `OPENWEBSERVERMANAGER_MASTER_KEY`。
- RDP 需要 Apache Guacamole `guacd` 與 FreeRDP runtime。

## 快速部署

```powershell
.\scripts\deploy.ps1
```

腳本會打包目前 Git HEAD，上傳至伺服器，建置前後端，寫入 systemd 服務，並監聽 `0.0.0.0:23876`。

自訂目標：

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## 手動 Linux 部署

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

核心環境變數：

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

生產環境建議使用 systemd 與 HTTPS 反向代理。

## 發布包

從 GitHub Releases 下載對應系統架構的壓縮包，解壓後執行：

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

## Agent 閘道

在管理後台建立 Agent 閘道並產生只顯示一次的註冊令牌，然後在可存取目標內網的節點執行：

```bash
OPENWEBSERVERMANAGER_AGENT_TOKEN='gateway_id.registration_secret' ./openwebservermanager-agent -server https://manager.example.com -name edge-office-1
```

Agent 只需主動連線管理端，不必開放入站連接埠。將 Agent 加入資產使用的閘道群組後，SSH/SFTP 會透過已驗證且可稽核的雙向 TCP 中繼；閘道不可用時不會靜默改為直連。反向代理應對 `/api/agent/` 關閉請求與回應緩衝並延長讀寫逾時。

## guacd

RDP 需要 `guacd`：

```bash
sudo systemctl enable --now guacd
```

配置 `OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1` 與 `OPENWEBSERVERMANAGER_GUACD_PORT=4822`。

Linux amd64 與 Windows amd64 發行包也內建通過測試的 `runtime/guacd/linux/bin/guacd` 和 `runtime/guacd/windows/bin/guacd.exe`。Windows 所需的 Cygwin DLL 已包含在發行包中。

## 首次初始化

開啟：

```text
http://<server-ip>:23876/login
```

建立第一個管理員密碼後才能進入控制台。

## 驗證

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```
