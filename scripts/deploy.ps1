param(
  [string]$HostName = "124.223.212.22",
  [string]$UserName = "ubuntu",
  [string]$KeyPath = "$env:USERPROFILE\.ssh\servermanager_deploy_rsa",
  [string]$RemoteRoot = "/opt/servermanager",
  [int]$Port = 23876
)

$ErrorActionPreference = "Stop"

$commit = (git rev-parse --short HEAD).Trim()
$archive = Join-Path $env:TEMP "servermanager-$commit.tar"
$remoteArchive = "/tmp/servermanager-$commit.tar"
$remoteScript = "/tmp/servermanager-deploy-$commit.sh"

git archive --format=tar --output $archive HEAD

$script = @"
set -euo pipefail

REMOTE_ROOT="$RemoteRoot"
PORT="$Port"
ARCHIVE="$remoteArchive"
APP_USER=`$(id -un)
APP_GROUP=`$(id -gn)

sudo mkdir -p "`$REMOTE_ROOT/src" "`$REMOTE_ROOT/bin" "`$REMOTE_ROOT/data" "`$REMOTE_ROOT/data/recordings" "`$REMOTE_ROOT/data/drives"
sudo chown -R "`$APP_USER:`$APP_GROUP" "`$REMOTE_ROOT"
rm -rf "`$REMOTE_ROOT/src"
mkdir -p "`$REMOTE_ROOT/src"
tar -xf "`$ARCHIVE" -C "`$REMOTE_ROOT/src"

cd "`$REMOTE_ROOT/src"
if [ -f frontend/package.json ]; then
  npm --prefix frontend ci
  npm --prefix frontend run build
fi
VERSION=`$(cat VERSION 2>/dev/null || echo dev)
COMMIT="$commit"
go mod tidy
go build -trimpath -ldflags "-s -w -X main.version=`$VERSION -X main.commit=`$COMMIT" -o "`$REMOTE_ROOT/bin/servermanager" ./cmd/servermanager

sudo chmod 0750 "`$REMOTE_ROOT" || true
sudo chmod 2770 "`$REMOTE_ROOT/data" "`$REMOTE_ROOT/data/recordings" "`$REMOTE_ROOT/data/drives" || true
if id guacd >/dev/null 2>&1; then
  sudo usermod -aG "`$APP_GROUP" guacd || true
fi

sudo tee /etc/systemd/system/servermanager.service >/dev/null <<UNIT
[Unit]
Description=ServerManager web server management console
After=network-online.target guacd.service
Wants=network-online.target guacd.service

[Service]
Type=simple
User=`$APP_USER
Group=`$APP_GROUP
WorkingDirectory=`$REMOTE_ROOT/src
Environment=SERVERMANAGER_ADDR=0.0.0.0:`$PORT
Environment=SERVERMANAGER_DATA_DIR=`$REMOTE_ROOT/data
Environment=SERVERMANAGER_VERSION=`$VERSION
Environment=SERVERMANAGER_GUACD_HOST=127.0.0.1
Environment=SERVERMANAGER_GUACD_PORT=4822
Environment=SERVERMANAGER_SHARED_DIR_MODE=0770
ExecStart=`$REMOTE_ROOT/bin/servermanager
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now guacd
sudo systemctl restart guacd
sudo systemctl enable --now servermanager
sudo systemctl restart servermanager
systemctl --no-pager --full status servermanager | sed -n '1,18p'
"@

$localScript = Join-Path $env:TEMP "servermanager-deploy-$commit.sh"
[System.IO.File]::WriteAllText($localScript, $script, [System.Text.UTF8Encoding]::new($false))

scp -i $KeyPath -o IdentitiesOnly=yes -P 22 $archive "${UserName}@${HostName}:$remoteArchive"
scp -i $KeyPath -o IdentitiesOnly=yes -P 22 $localScript "${UserName}@${HostName}:$remoteScript"
ssh -i $KeyPath -o IdentitiesOnly=yes -p 22 "${UserName}@${HostName}" "bash $remoteScript"

Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $localScript -Force -ErrorAction SilentlyContinue
