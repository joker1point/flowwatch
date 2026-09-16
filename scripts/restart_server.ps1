# Restart the flowwatch backend: kill EVERY listener on the port first
# (Windows allows duplicate binds, a stale process would keep serving),
# then start exactly one. ASCII-only on purpose: non-ASCII inside quoted
# strings has bitten this shell before (encoding misread eats the quote).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File restart_server.ps1 [-WaitSeconds 12]
param(
    [string]$Project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [int]$Port = 8788,
    [int]$WaitSeconds = 12
)

$ErrorActionPreference = 'SilentlyContinue'

$before = @(Get-NetTCPConnection -State Listen -LocalPort $Port | Select-Object -ExpandProperty OwningProcess)
if ($before.Count -gt 0) {
    Write-Output ("stopping old backend pids: " + ($before -join ', '))
    Stop-Process -Id $before -Force
    Start-Sleep -Seconds 2
}

$still = @(Get-NetTCPConnection -State Listen -LocalPort $Port | Select-Object -ExpandProperty OwningProcess)
if ($still.Count -gt 0) {
    Write-Output ("port still busy: " + ($still -join ', '))
    exit 1
}

Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "python server.py 1> _run\server.log 2>&1" -WorkingDirectory $Project -WindowStyle Hidden
Start-Sleep -Seconds $WaitSeconds

$listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port | Select-Object -ExpandProperty OwningProcess)
Write-Output ("LISTENERS: " + ($listeners -join ', '))
try {
    $health = Invoke-RestMethod "http://127.0.0.1:$Port/api/health" -TimeoutSec 8
    Write-Output ("HEALTH: " + ($health | ConvertTo-Json -Compress -Depth 4))
    $rates = Invoke-RestMethod "http://127.0.0.1:$Port/api/rates?limit=3" -TimeoutSec 8
    Write-Output ("TOTALS: " + ($rates.totals | ConvertTo-Json -Compress))
} catch {
    Write-Output ("FAIL: " + $_.Exception.Message)
    Get-Content (Join-Path $Project '_run\server.log') -Tail 15
}
