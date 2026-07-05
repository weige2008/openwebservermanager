# Hướng dẫn triển khai openwebservermanager

Ngôn ngữ mặc định: [简体中文](../../DEPLOYMENT.md)

Tài liệu này mô tả cách triển khai openwebservermanager trên Linux hoặc Windows và cung cấp workspace SSH/RDP trong trình duyệt.

Cổng mặc định: `23876`.

## Yêu cầu

- Go 1.25 hoặc mới hơn.
- Node.js 22 hoặc mới hơn để build frontend.
- `OPENWEBSERVERMANAGER_MASTER_KEY` ổn định.
- Với RDP: Apache Guacamole `guacd` và FreeRDP runtime.

## Triển khai nhanh

```powershell
.\scripts\deploy.ps1
```

Script đóng gói Git HEAD hiện tại, tải lên server, build frontend/backend, tạo systemd service và lắng nghe `0.0.0.0:23876`.

Tùy chỉnh đích:

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## Triển khai Linux thủ công

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

Biến môi trường chính:

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

Môi trường production nên dùng systemd và reverse proxy HTTPS.

## Gói phát hành

Tải archive phù hợp từ GitHub Releases rồi chạy:

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

RDP cần `guacd`:

```bash
sudo systemctl enable --now guacd
```

Cấu hình `OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1` và `OPENWEBSERVERMANAGER_GUACD_PORT=4822`.

## Khởi tạo lần đầu

Mở `http://<server-ip>:23876/login` và tạo mật khẩu quản trị viên đầu tiên.

## Kiểm tra

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```
