# openwebservermanager Deployment Guide

Default language: [简体中文](../../DEPLOYMENT.md)

This guide describes how to deploy openwebservermanager on Linux or Windows and expose browser-based SSH/RDP workspaces.

Default port: `23876`.

## Requirements

- Go 1.25 or newer.
- Node.js 22 or newer for frontend builds.
- A stable `OPENWEBSERVERMANAGER_MASTER_KEY`.
- For RDP: Apache Guacamole `guacd` and FreeRDP runtime.

## Quick Deployment

```powershell
.\scripts\deploy.ps1
```

The script archives the current Git HEAD, uploads it to the server, builds frontend and backend, writes a systemd service, and listens on `0.0.0.0:23876`.

Custom target:

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## Manual Linux Deployment

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

Create data directories:

```bash
sudo mkdir -p /opt/openwebservermanager/data/recordings /opt/openwebservermanager/data/drives
sudo chmod 2770 /opt/openwebservermanager/data /opt/openwebservermanager/data/recordings /opt/openwebservermanager/data/drives
```

Core environment:

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

Run it under systemd in production.

## Release Package

Download the matching archive from GitHub Releases, then run:

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

## Reverse Proxy

Use HTTPS in production and proxy WebSocket upgrade headers.

```nginx
location / {
  proxy_pass http://127.0.0.1:23876;
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
}
```

Set `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS=1` only when the proxy is trusted.

## Agent Gateway

Create an Agent gateway in the administration console and issue its one-time registration token. On a node that can reach the private target network, run:

```bash
OPENWEBSERVERMANAGER_AGENT_TOKEN='gateway_id.registration_secret' \
./openwebservermanager-agent -server https://manager.example.com -name edge-office-1
```

The same values can be supplied through `OPENWEBSERVERMANAGER_AGENT_SERVER`, `OPENWEBSERVERMANAGER_AGENT_TOKEN`, `OPENWEBSERVERMANAGER_AGENT_NAME`, and `OPENWEBSERVERMANAGER_AGENT_WORKERS`. The Agent only needs outbound access to the manager. Treat the registration token as a password.

Assign the Agent through a gateway group on the asset. SSH/SFTP traffic then uses authenticated and audited bidirectional TCP streams. If the gateway is unavailable, the connection fails instead of silently falling back to direct access. Reverse proxies must disable request/response buffering for `/api/agent/` and allow long read/write timeouts.

## guacd

RDP requires `guacd`.

```bash
sudo systemctl enable --now guacd
```

Then configure `OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1` and `OPENWEBSERVERMANAGER_GUACD_PORT=4822`.

Linux amd64 and Windows amd64 releases also include tested bundled runtimes at `runtime/guacd/linux/bin/guacd` and `runtime/guacd/windows/bin/guacd.exe`. The Windows package includes its Cygwin compatibility DLLs and does not require a separate Cygwin installation. Other architectures can continue using an external guacd.

## First Run

Open:

```text
http://<server-ip>:23876/login
```

Create the first administrator password before entering the console.

## Verification

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```
