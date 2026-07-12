# openwebservermanager

openwebservermanager is a self-hosted web console for managing server assets, encrypted connection accounts, browser-based SSH terminals, browser-based RDP desktops, file transfer, session recordings, and audit logs.

Default documentation: [简体中文](../../README.md)

Deployment guide: [English](DEPLOYMENT.en.md) | [简体中文](../../DEPLOYMENT.md)

## Features

- Go backend with embedded static frontend.
- Frontend stack aligned with NewAPI-style conventions: Rsbuild, React 19, TypeScript, Tailwind CSS v4, TanStack Router, TanStack Query, TanStack Table, Base UI, i18next, and Zustand.
- First-run administrator setup and authenticated console.
- SSH: WebSocket to SSH PTY bridge with password, private key, and private key passphrase authentication, plus policy-controlled SFTP browsing, upload, download, deletion, and audit logs.
- Agent gateway: remote nodes connect outbound to the manager and relay private SSH/SFTP traffic through authenticated, audited bidirectional TCP streams; routed sessions never silently fall back to direct access.
- RDP: Guacamole WebSocket tunnel to `guacd`; credentials stay server-side.
- Local JSON store with AES-GCM encrypted credential fields.
- RDP recording index and recording ZIP download for authenticated administrators.
- GitHub Actions release workflow for Linux, Windows, and macOS binaries.

## Quick Start

```powershell
go run ./cmd/openwebservermanager
```

Default URL: `http://127.0.0.1:23876`. Default data directory: `data/`.

Set a stable master key before storing real credentials:

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

Open `/login` on first run to create the administrator password.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `OPENWEBSERVERMANAGER_ADDR` | `127.0.0.1:23876` | HTTP listen address |
| `OPENWEBSERVERMANAGER_DATA_DIR` | `data` | Data, key, recordings, and drive directory |
| `OPENWEBSERVERMANAGER_MASTER_KEY` | generated `data/master.key` | Credential encryption key source |
| `OPENWEBSERVERMANAGER_GUACD_HOST` | bundled runtime lookup | External guacd host |
| `OPENWEBSERVERMANAGER_GUACD_PORT` | `4822` | guacd port |
| `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS` | `false` | Trust proxy headers |

## RDP and guacd

RDP requires Apache Guacamole `guacd`.

Lookup order:

1. `OPENWEBSERVERMANAGER_GUACD_HOST` and `OPENWEBSERVERMANAGER_GUACD_PORT`.
2. Bundled `runtime/guacd/<goos>/bin/guacd` or `guacd.exe` (legacy root layouts remain supported).

Linux amd64 and Windows amd64 releases include tested RDP/VNC runtimes. Other architectures can use an external guacd through the same environment variables.

Recordings are stored under `data/recordings/{session_id}/`; file transfer drives are stored under `data/drives/{session_id}/`.

## Development

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
npm --prefix frontend run build
go test ./...
```

## Deployment

See [DEPLOYMENT.en.md](DEPLOYMENT.en.md).

```powershell
.\scripts\deploy.ps1
```

## Releases

Update `VERSION`, then push a matching semantic version tag:

```powershell
git tag v1.0.11
git push origin v1.0.11
```

Release archives include the `openwebservermanager` and `openwebservermanager-agent` binaries, Chinese default docs, translated docs, `VERSION`, and `runtime/`.
