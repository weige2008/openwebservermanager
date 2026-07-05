# openwebservermanager デプロイガイド

既定言語: [简体中文](../../DEPLOYMENT.md)

このガイドでは、Linux または Windows に openwebservermanager をデプロイし、ブラウザ SSH/RDP ワークスペースを公開する方法を説明します。

既定ポート: `23876`。

## 要件

- Go 1.25 以上。
- frontend ビルド用 Node.js 22 以上。
- 安定した `OPENWEBSERVERMANAGER_MASTER_KEY`。
- RDP には Apache Guacamole `guacd` と FreeRDP runtime。

## クイックデプロイ

```powershell
.\scripts\deploy.ps1
```

スクリプトは現在の Git HEAD をアーカイブしてサーバーへアップロードし、frontend/backend をビルドし、systemd service を作成して `0.0.0.0:23876` で待ち受けます。

カスタム指定：

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## Linux 手動デプロイ

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

主要環境変数：

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

本番環境では systemd と HTTPS reverse proxy を推奨します。

## リリースパッケージ

GitHub Releases から対応するアーカイブをダウンロードし、実行します。

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876 \
OPENWEBSERVERMANAGER_DATA_DIR=./data \
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret \
./openwebservermanager
```

Windows PowerShell:

```powershell
$env:OPENWEBSERVERMANAGER_ADDR = "0.0.0.0:23876"
$env:OPENWEBSERVERMANAGER_DATA_DIR = ".\data"
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
.\openwebservermanager.exe
```

## guacd

RDP には `guacd` が必要です。

```bash
sudo systemctl enable --now guacd
```

`OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1` と `OPENWEBSERVERMANAGER_GUACD_PORT=4822` を設定します。

## 初回初期化

`http://<server-ip>:23876/login` を開き、最初の管理者パスワードを作成します。

## 検証

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```
