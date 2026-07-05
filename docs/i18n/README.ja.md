# openwebservermanager

openwebservermanager は、サーバー資産、暗号化された接続アカウント、ブラウザ SSH 端末、RDP デスクトップ、ファイル転送、セッション録画、監査ログを一元管理するセルフホスト型 Web コンソールです。

既定ドキュメント: [简体中文](../../README.md)

デプロイガイド: [日本語](DEPLOYMENT.ja.md) | [简体中文](../../DEPLOYMENT.md)

## 機能

- 静的 frontend を埋め込んだ Go backend。
- NewAPI 新 UI の方針に合わせた frontend: Rsbuild、React 19、TypeScript、Tailwind CSS v4、TanStack Router、TanStack Query、TanStack Table、Base UI、i18next、Zustand。
- 初回起動時の管理者作成と認証済みコンソール。
- SSH: WebSocket から SSH PTY へのブリッジ。パスワード、秘密鍵、passphrase に対応。
- RDP: Guacamole WebSocket tunnel で `guacd` に接続。認証情報はサーバー側に保持。
- AES-GCM で機密フィールドを暗号化するローカル JSON ストア。
- RDP 録画インデックスと管理者向け ZIP ダウンロード。
- GitHub Actions による Linux、Windows、macOS 向けリリースビルド。

## クイックスタート

```powershell
go run ./cmd/openwebservermanager
```

既定 URL は `http://127.0.0.1:23876`、データディレクトリは `data/` です。

実際の認証情報を保存する前に安定した master key を設定してください。

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

初回は `/login` を開き、管理者パスワードを作成します。

## RDP と guacd

RDP には Apache Guacamole `guacd` が必要です。`OPENWEBSERVERMANAGER_GUACD_HOST` と `OPENWEBSERVERMANAGER_GUACD_PORT` を設定するか、`runtime/guacd/<goos>/` にバイナリを配置してください。

録画は `data/recordings/{session_id}/`、ファイル転送用 drive は `data/drives/{session_id}/` に保存されます。

## 開発

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
npm --prefix frontend run build
go test ./...
```

## デプロイ

[DEPLOYMENT.ja.md](DEPLOYMENT.ja.md) を参照してください。

```powershell
.\scripts\deploy.ps1
```

## リリース

`VERSION` を更新し、対応する semantic version tag を push します。

```powershell
git tag v1.0.11
git push origin v1.0.11
```
