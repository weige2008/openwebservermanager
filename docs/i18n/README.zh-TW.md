# openwebservermanager

openwebservermanager 是一個自託管的網頁端伺服器管理控制台，用於在瀏覽器中集中管理伺服器資產、加密連線帳號、線上 SSH 終端、線上 RDP 桌面、檔案傳輸、工作階段錄影與稽核日誌。

預設文件：[简体中文](../../README.md)

部署指南：[繁體中文](DEPLOYMENT.zh-TW.md) | [简体中文](../../DEPLOYMENT.md)

## 功能特色

- Go 後端內嵌靜態前端，單一二進位即可執行。
- 前端技術棧對齊 NewAPI 新版 UI：Rsbuild、React 19、TypeScript、Tailwind CSS v4、TanStack Router、TanStack Query、TanStack Table、Base UI、i18next、Zustand。
- 首次啟動建立管理員密碼，登入後才可查看資產、帳號、工作階段與稽核資料。
- SSH：WebSocket 到 SSH PTY 橋接，支援密碼、私鑰與 passphrase，並提供受授權策略控制的 SFTP 檔案瀏覽、上傳、下載、刪除與稽核日誌。
- Agent 閘道：遠端節點主動連線管理端，透過已驗證且可稽核的雙向 TCP 中繼存取內網 SSH/SFTP 資產；已設定閘道的工作階段不會靜默改為直連。
- RDP：透過 Guacamole WebSocket tunnel 連線 `guacd`，真實憑證只在服務端使用。
- 本機 JSON 資料存放，憑證敏感欄位使用 AES-GCM 加密。
- RDP 錄影索引與管理員下載入口。
- GitHub Actions 自動建置 Linux、Windows、macOS 發布包。

## 快速開始

```powershell
go run ./cmd/openwebservermanager
```

預設地址為 `http://127.0.0.1:23876`，預設資料目錄為 `data/`。

正式保存憑證前請設定穩定主密鑰：

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

首次執行時開啟 `/login` 建立管理員密碼。

## RDP 與 guacd

RDP 需要 Apache Guacamole `guacd`。系統會優先使用外部 `OPENWEBSERVERMANAGER_GUACD_HOST` / `OPENWEBSERVERMANAGER_GUACD_PORT`，否則查找 `runtime/guacd/<goos>/guacd` 或 `guacd.exe`。

錄影保存於 `data/recordings/{session_id}/`，檔案傳輸 drive 目錄保存於 `data/drives/{session_id}/`。

## 開發

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
npm --prefix frontend run build
go test ./...
```

## 部署與發布

部署請見 [DEPLOYMENT.zh-TW.md](DEPLOYMENT.zh-TW.md)。

```powershell
.\scripts\deploy.ps1
```

發布時更新 `VERSION`，再推送對應 tag：

```powershell
git tag v1.0.11
git push origin v1.0.11
```
