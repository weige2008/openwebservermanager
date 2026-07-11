param(
  [string]$HostName = "124.223.212.22",
  [string]$UserName = "ubuntu",
  [string]$KeyPath = $(if (Test-Path -LiteralPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa") { "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" } else { "$env:USERPROFILE\.ssh\servermanager_deploy_rsa" }),
  [string]$RemoteRoot = "/opt/openwebservermanager",
  [int]$Port = 23876
)

$ErrorActionPreference = "Stop"

$commit = (git rev-parse --short HEAD).Trim()
$archive = Join-Path $env:TEMP "openwebservermanager-$commit.tar"
$remoteArchive = "/tmp/openwebservermanager-$commit.tar"
$remoteScript = "/tmp/openwebservermanager-deploy-$commit.sh"

git archive --format=tar --output $archive HEAD

$script = @"
set -euo pipefail

REMOTE_ROOT="$RemoteRoot"
LEGACY_ROOT="/opt/servermanager"
PORT="$Port"
ARCHIVE="$remoteArchive"
APP_USER=`$(id -un)
APP_GROUP=`$(id -gn)

sudo systemctl stop servermanager 2>/dev/null || true
sudo systemctl disable servermanager 2>/dev/null || true
sudo mkdir -p "`$REMOTE_ROOT/src" "`$REMOTE_ROOT/bin" "`$REMOTE_ROOT/data" "`$REMOTE_ROOT/data/recordings" "`$REMOTE_ROOT/data/drives"
if [ ! -f "`$REMOTE_ROOT/data/openwebservermanager.json" ] && [ -d "`$LEGACY_ROOT/data" ]; then
  sudo cp -a "`$LEGACY_ROOT/data/." "`$REMOTE_ROOT/data/"
fi
sudo chown -R "`$APP_USER:`$APP_GROUP" "`$REMOTE_ROOT"
rm -rf "`$REMOTE_ROOT/src"
mkdir -p "`$REMOTE_ROOT/src"
tar -xf "`$ARCHIVE" -C "`$REMOTE_ROOT/src"

cd "`$REMOTE_ROOT/src"
if [ -f scripts/install-guacenc-linux.sh ]; then
  sudo bash scripts/install-guacenc-linux.sh
fi
if [ -f frontend/package.json ]; then
  npm --prefix frontend ci
  npm --prefix frontend run build
fi
VERSION=`$(cat VERSION 2>/dev/null || echo dev)
COMMIT="$commit"
go mod tidy
go build -trimpath -ldflags "-s -w -X main.version=`$VERSION -X main.commit=`$COMMIT" -o "`$REMOTE_ROOT/bin/openwebservermanager" ./cmd/openwebservermanager
go build -trimpath -ldflags "-s -w -X main.version=`$VERSION -X main.commit=`$COMMIT" -o "`$REMOTE_ROOT/bin/openwebservermanager-agent" ./cmd/openwebservermanager-agent

sudo chmod 0750 "`$REMOTE_ROOT" || true
sudo chmod 2770 "`$REMOTE_ROOT/data" "`$REMOTE_ROOT/data/recordings" "`$REMOTE_ROOT/data/drives" || true
if id guacd >/dev/null 2>&1; then
  sudo usermod -aG "`$APP_GROUP" guacd || true
fi

sudo tee /etc/systemd/system/openwebservermanager.service >/dev/null <<UNIT
[Unit]
Description=openwebservermanager web server management console
After=network-online.target guacd.service
Wants=network-online.target guacd.service

[Service]
Type=simple
User=`$APP_USER
Group=`$APP_GROUP
WorkingDirectory=`$REMOTE_ROOT/src
Environment=OPENWEBSERVERMANAGER_ADDR=0.0.0.0:`$PORT
Environment=OPENWEBSERVERMANAGER_DATA_DIR=`$REMOTE_ROOT/data
Environment=OPENWEBSERVERMANAGER_VERSION=`$VERSION
Environment=OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
Environment=OPENWEBSERVERMANAGER_GUACD_PORT=4822
Environment=OPENWEBSERVERMANAGER_GUACENC_PATH=/usr/local/bin/guacenc
Environment=OPENWEBSERVERMANAGER_FFMPEG_PATH=/usr/bin/ffmpeg
Environment=OPENWEBSERVERMANAGER_RECORDING_TRANSCODE_TIMEOUT_SECONDS=1800
Environment=OPENWEBSERVERMANAGER_SHARED_DIR_MODE=0770
ExecStart=`$REMOTE_ROOT/bin/openwebservermanager
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now guacd
sudo systemctl restart guacd
sudo systemctl enable --now openwebservermanager
sudo systemctl restart openwebservermanager
systemctl --no-pager --full status openwebservermanager | sed -n '1,18p'
"@

$localScript = Join-Path $env:TEMP "openwebservermanager-deploy-$commit.sh"
[System.IO.File]::WriteAllText($localScript, $script, [System.Text.UTF8Encoding]::new($false))

scp -i $KeyPath -o IdentitiesOnly=yes -P 22 $archive "${UserName}@${HostName}:$remoteArchive"
scp -i $KeyPath -o IdentitiesOnly=yes -P 22 $localScript "${UserName}@${HostName}:$remoteScript"
ssh -i $KeyPath -o IdentitiesOnly=yes -p 22 "${UserName}@${HostName}" "bash $remoteScript"

Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $localScript -Force -ErrorAction SilentlyContinue
