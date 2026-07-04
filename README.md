# openwebservermanager

openwebservermanager is a self-hosted web console for browser-based SSH and RDP access. Phase one focuses on server assets, encrypted connection accounts, online SSH terminals, online RDP desktops, file transfer, session recording, and audit logs.

## Features

- Go backend with embedded static frontend.
- Frontend stack aligned with NewAPI-style conventions: Rsbuild, React 19, TypeScript, Tailwind CSS v4, TanStack Router, TanStack Query, TanStack Table, Base UI, i18next, and Zustand.
- First-run administrator setup and authenticated console.
- SSH: WebSocket to SSH PTY bridge with password, private key, and private key passphrase authentication.
- RDP: Guacamole WebSocket tunnel to `guacd`; credentials stay server-side.
- Local JSON data store with AES-GCM encrypted credential fields.
- RDP recording index and recording ZIP download for authenticated administrators.
- GitHub Actions release workflow for Linux, Windows, and macOS binaries.

## Run Locally

```powershell
go run ./cmd/openwebservermanager
```

The default listener is `http://127.0.0.1:23876` and the default data directory is `data/`.

Set a stable master key before using real credentials:

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

If no administrator exists, open `/login` and create the first admin password. Passwords are stored as bcrypt hashes. Plaintext credentials are encrypted before persistence and are never returned by API responses.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENWEBSERVERMANAGER_ADDR` | `127.0.0.1:23876` | HTTP listen address |
| `OPENWEBSERVERMANAGER_DATA_DIR` | `data` | Data, key, recordings, and drive directory |
| `OPENWEBSERVERMANAGER_MASTER_KEY` | generated `data/master.key` | Credential encryption key source |
| `OPENWEBSERVERMANAGER_GUACD_HOST` | bundled runtime lookup | External guacd host |
| `OPENWEBSERVERMANAGER_GUACD_PORT` | `4822` | guacd port |
| `OPENWEBSERVERMANAGER_GUACD_RUNTIME` | `runtime/guacd` | Bundled guacd runtime root |
| `OPENWEBSERVERMANAGER_SHARED_DIR_MODE` | `0770` | Recording/drive directory mode for guacd sharing |
| `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-*` and `X-Real-IP` headers |
| `OPENWEBSERVERMANAGER_VERSION` | build version | Version exposed in public config |
| `OPENWEBSERVERMANAGER_GITHUB_URL` | project repository | GitHub link shown in the UI |
| `OPENWEBSERVERMANAGER_COPYRIGHT` | weige2008 copyright | Copyright text shown in the UI |

## RDP and guacd

RDP requires Apache Guacamole `guacd`.

Lookup order:

1. Use `OPENWEBSERVERMANAGER_GUACD_HOST` and `OPENWEBSERVERMANAGER_GUACD_PORT` when set.
2. Use bundled `runtime/guacd/<goos>/guacd` or `guacd.exe`.

Expected bundled paths:

- Linux: `runtime/guacd/linux/guacd`
- Windows: `runtime/guacd/windows/guacd.exe`

RDP recordings are stored under `data/recordings/{session_id}/`. Drive transfer directories are stored under `data/drives/{session_id}/`.

## Security Notes

- Business APIs require an authenticated admin session.
- Unsafe API methods reject cross-origin requests when an `Origin` header is present.
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when served through HTTPS.
- Login failures are rate-limited per username and client IP.
- SSH host keys are stored in `data/known_hosts`; unknown hosts are accepted on first use and later mismatches fail.
- WebSocket upgrades validate version, key, masking, frame size, and unsupported fragmentation.
- `X-Forwarded-*` headers are ignored unless `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS=1`.

## Development

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
```

Production frontend builds write to `cmd/openwebservermanager/static/` and are embedded by Go.

```powershell
npm --prefix frontend run build
go test ./...
```

## Deployment

```powershell
.\scripts\deploy.ps1
```

The default script deploys to `/opt/openwebservermanager`, builds the frontend and backend on the server, and runs the service on port `23876`.

## Releases

The project version starts at `1.0.0` in `VERSION`. Increment patch, minor, or major versions for each update, then push a matching semantic version tag to trigger the GitHub Actions release workflow:

```powershell
git tag v1.0.6
git push origin v1.0.6
```

The workflow builds:

- `linux-amd64`
- `linux-arm64`
- `windows-amd64`
- `windows-arm64`
- `darwin-amd64`
- `darwin-arm64`

Release archives include the `openwebservermanager` binary, `README.md`, `VERSION`, and the `runtime/` directory.
