# 以管理员身份运行某个诊断脚本（PowerShell 的 `*>` 会把子进程 UTF-8 输出按 GBK 再存 UTF-16，
# 会把日志变成 mojibake；这里用 cmd 直接重定向，编码干净）。本文件保持纯 ASCII。
#
# 用法（在【管理员】PowerShell 里）:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_elevated.ps1 scripts\etw_probe_logman.py
param(
    [Parameter(Mandatory = $true)][string]$Script,
    [string]$Project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)
$ErrorActionPreference = 'Continue'
$target = Join-Path $Project $Script
$name = [IO.Path]::GetFileNameWithoutExtension($target)
$log = Join-Path $Project ("_run\" + $name + ".log")
New-Item -ItemType Directory -Force -Path (Join-Path $Project '_run') | Out-Null
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "python `"$target`" 1> `"$log`" 2>&1" -WorkingDirectory $Project -WindowStyle Hidden -Wait
Write-Output ("log: " + $log)
Get-Content $log -Encoding UTF8
