param(
  [string]$OutputDir = "runtime/guacd/windows",
  [string]$WorkDir = $(Join-Path $env:TEMP "openwebservermanager-guacd-windows"),
  [string]$GuacamoleVersion = "1.5.5",
  [string]$CygwinMirror = "https://mirrors.kernel.org/sourceware/cygwin/",
  [string]$CygwinProxy = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$outputRoot = if ([IO.Path]::IsPathRooted($OutputDir)) { [IO.Path]::GetFullPath($OutputDir) } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDir)) }
$workRoot = [IO.Path]::GetFullPath($WorkDir)
$cygwinRoot = Join-Path $workRoot "cygwin64"
$setupPath = Join-Path $workRoot "setup-x86_64.exe"
$archivePath = Join-Path $workRoot "guacamole-server-$GuacamoleVersion.tar.gz"
$sourceRoot = Join-Path $workRoot "guacamole-server-$GuacamoleVersion"
$patchPath = Join-Path $repoRoot "scripts/guacd/guacamole-server-1.5.5-cygwin.patch"
$packageCache = Join-Path $workRoot "packages"

New-Item -ItemType Directory -Force -Path $workRoot, $packageCache | Out-Null
if (!(Test-Path -LiteralPath $setupPath)) {
  Invoke-WebRequest -Uri "https://cygwin.com/setup-x86_64.exe" -OutFile $setupPath
}

$packages = @(
  "autoconf", "automake", "gcc-core", "libtool", "make", "patch", "pkg-config", "tar", "wget",
  "libcairo-devel", "libfreerdp2-devel", "libgcrypt-devel", "libjpeg-devel", "libpng-devel",
  "libssl-devel", "libuuid-devel", "libvncserver-devel", "libwebp-devel", "libwinpr2-devel"
) -join ","
$registryPath = "HKCU:\Software\Cygwin\setup"
$existingRoot = (Get-ItemProperty -Path $registryPath -Name rootdir -ErrorAction SilentlyContinue).rootdir
$setupArguments = @(
  "-q", "unattended", "-B", "-d", "-n", "-O", "-R", $cygwinRoot,
  "-l", $packageCache, "-s", $CygwinMirror, "-P", $packages
)
if ($CygwinProxy) {
  $setupArguments += @("-p", $CygwinProxy)
}
try {
  $setup = Start-Process -FilePath $setupPath -ArgumentList $setupArguments -WindowStyle Hidden -Wait -PassThru
} finally {
  if ($null -ne $existingRoot) {
    New-Item -Path $registryPath -Force | Out-Null
    Set-ItemProperty -Path $registryPath -Name rootdir -Value $existingRoot
  } else {
    Remove-ItemProperty -Path $registryPath -Name rootdir -ErrorAction SilentlyContinue
  }
}
if ($setup.ExitCode -ne 0) {
  throw "Cygwin setup failed with exit code $($setup.ExitCode)"
}

if (!(Test-Path -LiteralPath $archivePath)) {
  Invoke-WebRequest -Uri "https://archive.apache.org/dist/guacamole/$GuacamoleVersion/source/guacamole-server-$GuacamoleVersion.tar.gz" -OutFile $archivePath
}
if (Test-Path -LiteralPath $sourceRoot) {
  Remove-Item -LiteralPath $sourceRoot -Recurse -Force
}
tar -xzf $archivePath -C $workRoot
git -C $sourceRoot apply --whitespace=error-all $patchPath

$bash = Join-Path $cygwinRoot "bin/bash.exe"
$sourceCygwin = (& (Join-Path $cygwinRoot "bin/cygpath.exe") -u $sourceRoot).Trim()
$buildScript = @"
set -euo pipefail
cd '$sourceCygwin'
autoreconf -fi
./configure \
  --prefix=/usr \
  --without-winsock \
  --with-freerdp-plugin-dir=/usr/lib/freerdp2 \
  --disable-guacenc \
  --disable-guaclog \
  --disable-kubernetes \
  --disable-ssh-agent \
  --enable-allow-freerdp-snapshots
sed -i '/^#define __BSD_VISIBLE 1`$/d' config.h
make -j2
rm -rf /tmp/openwebservermanager-guacd-stage
make DESTDIR=/tmp/openwebservermanager-guacd-stage install
"@
$buildScriptPath = Join-Path $workRoot "build-guacd.sh"
[IO.File]::WriteAllText($buildScriptPath, $buildScript.Replace("`r`n", "`n") + "`n", [Text.UTF8Encoding]::new($false))
$buildScriptCygwin = (& (Join-Path $cygwinRoot "bin/cygpath.exe") -u $buildScriptPath).Trim()
& $bash -l $buildScriptCygwin
if ($LASTEXITCODE -ne 0) {
  throw "guacd Cygwin build failed with exit code $LASTEXITCODE"
}

$installRoot = Join-Path $cygwinRoot "tmp/openwebservermanager-guacd-stage/usr"
if (Test-Path -LiteralPath $outputRoot) {
  Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
$binDir = (New-Item -ItemType Directory -Force -Path (Join-Path $outputRoot "bin")).FullName
$pluginDir = (New-Item -ItemType Directory -Force -Path (Join-Path $outputRoot "usr/lib/freerdp2")).FullName
$homeDir = (New-Item -ItemType Directory -Force -Path (Join-Path $outputRoot "home")).FullName

Copy-Item -LiteralPath (Join-Path $installRoot "sbin/guacd.exe") -Destination (Join-Path $binDir "guacd.exe")
Copy-Item -Path (Join-Path $installRoot "bin/*.dll") -Destination $binDir
Copy-Item -Path (Join-Path $installRoot "lib/freerdp2/*.dll") -Destination $pluginDir
Copy-Item -LiteralPath (Join-Path $installRoot "bin/cygguac-client-rdp-0.dll") -Destination (Join-Path $binDir "libguac-client-rdp.so")
Copy-Item -LiteralPath (Join-Path $installRoot "bin/cygguac-client-vnc-0.dll") -Destination (Join-Path $binDir "libguac-client-vnc.so")

$oldPath = $env:PATH
try {
  $env:PATH = "$($installRoot)\bin;$($cygwinRoot)\bin;$oldPath"
  $targets = @(
    Get-Item -LiteralPath (Join-Path $installRoot "sbin/guacd.exe")
    Get-ChildItem -LiteralPath (Join-Path $installRoot "bin") -Filter "*.dll" -File
    Get-ChildItem -LiteralPath (Join-Path $installRoot "lib/freerdp2") -Filter "*.dll" -File
  )
  $dependencies = @{}
  foreach ($target in $targets) {
    $lines = & (Join-Path $cygwinRoot "bin/cygcheck.exe") $target.FullName 2>$null
    foreach ($line in $lines) {
      $path = $line.Trim()
      if ($path -like "$cygwinRoot\bin\*.dll") {
        $dependencies[$path] = $true
      }
    }
  }
  foreach ($path in $dependencies.Keys) {
    Copy-Item -LiteralPath $path -Destination $binDir -Force
  }
} finally {
  $env:PATH = $oldPath
}

Copy-Item -LiteralPath (Join-Path $sourceRoot "LICENSE") -Destination (Join-Path $outputRoot "LICENSE.apache-guacamole.txt")
Copy-Item -LiteralPath (Join-Path $sourceRoot "NOTICE") -Destination (Join-Path $outputRoot "NOTICE.apache-guacamole.txt")
$manifest = [ordered]@{
  runtime = "guacd"
  version = $GuacamoleVersion
  platform = "windows-amd64"
  toolchain = "cygwin"
  protocols = @("rdp", "vnc")
  executable = "bin/guacd.exe"
  files = 0
  size_bytes = 0
}
$manifestPath = Join-Path $outputRoot "manifest.json"
for ($attempt = 0; $attempt -lt 3; $attempt++) {
  $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8
  $runtimeFiles = Get-ChildItem -LiteralPath $outputRoot -Recurse -File
  $manifest.files = $runtimeFiles.Count
  $manifest.size_bytes = ($runtimeFiles | Measure-Object Length -Sum).Sum
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding utf8

Write-Host "Built portable Windows guacd runtime at $outputRoot"
Write-Host "Files: $($manifest.files), size: $([math]::Round($manifest.size_bytes / 1MB, 1)) MB"
