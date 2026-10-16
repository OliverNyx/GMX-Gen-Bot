# Starts CapSkip (if needed), waits for local API, then runs gmxgen with CapSkip.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$capSkipExe = "C:\Program Files\CapSkip\CapSkip.exe"
$gmxgen = Join-Path $root "gmxgen.exe"
$apiBase = if ($env:CAPSKIP_URL) { $env:CAPSKIP_URL.TrimEnd('/') } else { "http://127.0.0.1:8080" }
$waitSec = if ($env:CAPSKIP_WAIT_SEC) { [int]$env:CAPSKIP_WAIT_SEC } else { 300 }

if (-not (Test-Path $gmxgen)) {
    & "C:\Program Files\Go\bin\go.exe" build -o $gmxgen (Join-Path $root "cmd\gmxgen")
}

if (-not (Get-Process -Name "CapSkip" -ErrorAction SilentlyContinue)) {
    if (-not (Test-Path $capSkipExe)) {
        throw "CapSkip not installed. Install from https://capskip.com/download/CapSkipInstaller.msi"
    }
    Write-Host "Starting CapSkip..."
    Start-Process -FilePath $capSkipExe | Out-Null
}

Write-Host "Waiting up to $waitSec s for CapSkip API at $apiBase ..."
$ready = $false
$deadline = (Get-Date).AddSeconds($waitSec)
while ((Get-Date) -lt $deadline) {
    try {
        $probe = Invoke-WebRequest -Uri "$apiBase/in.php" -Method POST `
            -Body "method=captchafox&sitekey=sk_test&pageurl=https://signup.gmx.com/&json=1" `
            -UseBasicParsing -TimeoutSec 5
        if ($probe.StatusCode -eq 200 -and $probe.Content -match '"request"') {
            $ready = $true
            break
        }
    } catch {
        # connection refused until user logs in and API is enabled
    }
    Start-Sleep -Seconds 5
}

if (-not $ready) {
    Write-Host ""
    Write-Host "CapSkip API is not reachable at $apiBase"
    Write-Host "Open CapSkip on this machine, sign in, and complete setup (API on port 8080, 2Captcha emulator)."
    Write-Host "Then re-run: .\scripts\run-with-capskip.ps1"
    exit 2
}

Write-Host "CapSkip API is up. Running gmxgen..."
if (-not $env:PROXY_USER -or -not $env:PROXY_PASS) {
    throw "Set PROXY_USER and PROXY_PASS before running."
}

& $gmxgen -capskip-url $apiBase @args
exit $LASTEXITCODE
