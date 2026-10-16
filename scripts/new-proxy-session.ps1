# Writes/updates .env proxy settings. Session is NOT pinned — gmxgen rotates _session-* each run (new IP per account).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$basePass = $env:IPROYAL_PASS_BASE
if (-not $basePass) {
    $basePass = "DoDeCVx1TbQBGGCB_country-us_lifetime-168h"
}
$pass = $basePass -replace '_session-[^_]+', ''

$lines = @(
    "PROXY_HOST=geo.iproyal.com",
    "PROXY_PORT=12321",
    "PROXY_USER=A42DKiBqFozMn6xu",
    "PROXY_PASS=$pass",
    "CAPZY_API_KEY=$($env:CAPZY_API_KEY)"
)
$envPath = Join-Path $root ".env"
$lines | Set-Content -Path $envPath -Encoding UTF8

Get-Content $envPath | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') {
        Set-Item -Path "Env:$($matches[1].Trim())" -Value $matches[2].Trim()
    }
}
Write-Host "Updated $envPath (no fixed PROXY_SESSION)."
Write-Host "Each gmxgen run uses -rotate-proxy-session=true by default → new IP per account."
