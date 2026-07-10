# openwebservermanager

openwebservermanager là bảng điều khiển web tự lưu trữ để quản lý tài sản máy chủ, tài khoản kết nối được mã hóa, terminal SSH trong trình duyệt, desktop RDP, truyền tệp, ghi phiên và nhật ký kiểm toán.

Tài liệu mặc định: [简体中文](../../README.md)

Hướng dẫn triển khai: [Tiếng Việt](DEPLOYMENT.vi.md) | [简体中文](../../DEPLOYMENT.md)

## Tính năng

- Backend Go nhúng frontend tĩnh.
- Frontend theo phong cách NewAPI mới: Rsbuild, React 19, TypeScript, Tailwind CSS v4, TanStack Router, TanStack Query, TanStack Table, Base UI, i18next và Zustand.
- Tạo quản trị viên lần đầu và console yêu cầu đăng nhập.
- SSH: cầu nối WebSocket tới SSH PTY, hỗ trợ mật khẩu, khóa riêng và passphrase, cùng duyệt SFTP, tải lên, tải xuống, xóa và nhật ký kiểm toán được kiểm soát bằng chính sách ủy quyền.
- RDP: Guacamole WebSocket tunnel tới `guacd`; thông tin xác thực chỉ nằm ở server.
- Lưu trữ JSON cục bộ, mã hóa trường nhạy cảm bằng AES-GCM.
- Chỉ mục ghi phiên RDP và tải ZIP cho quản trị viên.
- GitHub Actions build cho Linux, Windows và macOS.

## Chạy nhanh

```powershell
go run ./cmd/openwebservermanager
```

URL mặc định: `http://127.0.0.1:23876`. Thư mục dữ liệu mặc định: `data/`.

Đặt master key ổn định trước khi lưu thông tin xác thực thật:

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

Lần chạy đầu tiên, mở `/login` để tạo mật khẩu quản trị viên.

## RDP và guacd

RDP cần Apache Guacamole `guacd`. Cấu hình `OPENWEBSERVERMANAGER_GUACD_HOST` và `OPENWEBSERVERMANAGER_GUACD_PORT`, hoặc đặt binary vào `runtime/guacd/<goos>/`.

Bản ghi nằm trong `data/recordings/{session_id}/`; thư mục truyền tệp nằm trong `data/drives/{session_id}/`.

## Phát triển

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
npm --prefix frontend run build
go test ./...
```

## Triển khai

Xem [DEPLOYMENT.vi.md](DEPLOYMENT.vi.md).

```powershell
.\scripts\deploy.ps1
```

## Phát hành

Cập nhật `VERSION`, sau đó push tag semantic version tương ứng:

```powershell
git tag v1.0.11
git push origin v1.0.11
```
