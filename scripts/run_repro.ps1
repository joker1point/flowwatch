# Run the history repro under a watchdog: if it hangs, kill it and still show how far it got.
# ASCII only (non-ASCII inside quotes has broken this shell before).
param(
    [string]$Qa = $PSScriptRoot,
    [int]$WaitSeconds = 20
)
$ErrorActionPreference = 'SilentlyContinue'

Get-CimInstance Win32_Process -Filter "Name like '%python%'" |
    Where-Object { $_.CommandLine -like '*repro_history*' } |
    ForEach-Object { Write-Output ('killing stale repro pid ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }

Remove-Item (Join-Path $Qa 'repro.log') -ErrorAction SilentlyContinue
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'python repro_history.py > repro.log 2>&1' -WorkingDirectory $Qa -WindowStyle Hidden
Start-Sleep -Seconds $WaitSeconds

Get-CimInstance Win32_Process -Filter "Name like '%python%'" |
    Where-Object { $_.CommandLine -like '*repro_history*' } |
    ForEach-Object { Write-Output ('STILL RUNNING (hung) -> killing pid ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }

Write-Output '=== repro.log ==='
Get-Content (Join-Path $Qa 'repro.log')
