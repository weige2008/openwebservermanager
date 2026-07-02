param(
  [string]$HostName = "124.223.212.22",
  [string]$UserName = "ubuntu",
  [string]$KeyPath = "$env:USERPROFILE\.ssh\servermanager_deploy_rsa",
  [string]$RemoteRoot = "/opt/servermanager",
  [int]$Port = 8080
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
go mod tidy
go build -o "`$REMOTE_ROOT/bin/servermanager" ./cmd/servermanager

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
Environment=SERVERMANAGER_GUACD_HOST=127.0.0.1
Environment=SERVERMANAGER_GUACD_PORT=4822
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
