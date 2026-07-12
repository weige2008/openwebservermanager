param(
  [string]$RuntimeDir = "runtime/guacd/windows",
  [int]$Port = 24822
)

$ErrorActionPreference = "Stop"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$runtimeRoot = if ([IO.Path]::IsPathRooted($RuntimeDir)) { [IO.Path]::GetFullPath($RuntimeDir) } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $RuntimeDir)) }
$binDir = Join-Path $runtimeRoot "bin"
$guacdPath = Join-Path $binDir "guacd.exe"
if (!(Test-Path -LiteralPath $guacdPath)) {
  throw "guacd.exe was not found at $guacdPath"
}

$registryPath = "HKCU:\Software\Cygwin\setup"
$existingRoot = (Get-ItemProperty -Path $registryPath -Name rootdir -ErrorAction SilentlyContinue).rootdir
New-Item -Path $registryPath -Force | Out-Null
Set-ItemProperty -Path $registryPath -Name rootdir -Value $runtimeRoot
$oldPath = $env:PATH
$stdout = Join-Path $runtimeRoot "guacd-smoke.stdout.log"
$stderr = Join-Path $runtimeRoot "guacd-smoke.stderr.log"
$process = $null
$passed = $false

function Read-GuacdArgs([string]$Protocol) {
  $client = [Net.Sockets.TcpClient]::new("127.0.0.1", $Port)
  try {
    $stream = $client.GetStream()
    $payload = [Text.Encoding]::UTF8.GetBytes("6.select,$($Protocol.Length).$Protocol;")
    $stream.Write($payload, 0, $payload.Length)
    $buffer = New-Object byte[] 65536
    $read = $stream.Read($buffer, 0, $buffer.Length)
    return [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
  } finally {
    $client.Close()
  }
}

try {
  $env:PATH = "$binDir;$env:SystemRoot\System32"
  $env:HOME = Join-Path $runtimeRoot "home"
  $process = Start-Process -FilePath $guacdPath -ArgumentList @("-b", "127.0.0.1", "-l", $Port, "-f", "-L", "debug") -WorkingDirectory $binDir -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
  $ready = $false
  for ($attempt = 0; $attempt -lt 80; $attempt++) {
    Start-Sleep -Milliseconds 100
    if ($process.HasExited) {
      break
    }
    try {
      $probe = [Net.Sockets.TcpClient]::new("127.0.0.1", $Port)
      $probe.Close()
      $ready = $true
      break
    } catch {
    }
  }
  if (!$ready) {
    throw "portable guacd did not listen on port $Port"
  }

  foreach ($protocol in @("rdp", "vnc")) {
    $args = Read-GuacdArgs $protocol
    if (!$args.StartsWith("4.args,") -or !$args.Contains("8.hostname")) {
      throw "$protocol plugin did not return a valid Guacamole args instruction: $args"
    }
    Start-Sleep -Milliseconds 250
    if ($process.HasExited) {
      throw "guacd exited after $protocol handshake with code $($process.ExitCode)"
    }
  }

  Write-Host "Windows guacd RDP/VNC smoke test passed on port $Port"
  $passed = $true
} finally {
  if ($process -and !$process.HasExited) {
    Stop-Process -Id $process.Id -Force
    $process.WaitForExit()
  }
  $env:PATH = $oldPath
  Remove-Item Env:HOME -ErrorAction SilentlyContinue
  if ($null -ne $existingRoot) {
    Set-ItemProperty -Path $registryPath -Name rootdir -Value $existingRoot
  } else {
    Remove-ItemProperty -Path $registryPath -Name rootdir -ErrorAction SilentlyContinue
  }
  if ($passed) {
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
  } else {
    Write-Warning "guacd smoke logs were preserved at $stdout and $stderr"
  }
}
