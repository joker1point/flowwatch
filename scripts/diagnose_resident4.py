#!/usr/bin/env python3
"""diagnose_resident 第 4 步：系统开关机时间线（2026-10-15）。

判断自启失效的性质：10-07 之后系统重启过吗？
  · 没重启 → 自启触发正常，是进程起来后死掉（守护/自愈缺位问题）
  · 重启过 → 要么自启没触发，要么触发了但启动失败（自启可靠性问题）
"""
from __future__ import annotations

import subprocess

PS = r"""
$os = Get-CimInstance Win32_OperatingSystem
$up = $os.LocalDateTime - $os.LastBootUpTime
Write-Output ("LastBoot: " + $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss"))
Write-Output ("Uptime:   " + $up.Days + "d " + $up.Hours + "h " + $up.Minutes + "m")
$ev = Get-WinEvent -FilterHashtable @{LogName="System"; Id=6005,6006,1074} -MaxEvents 6 -ErrorAction SilentlyContinue
foreach ($e in $ev) {
  $tag = switch ($e.Id) { 6005 {"开机"} 6006 {"关机"} 1074 {"关机(用户/进程发起)"} }
  Write-Output ($e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") + "  " + $tag)
}
"""

if __name__ == "__main__":
    r = subprocess.run(["powershell", "-NoProfile", "-Command", PS],
                       capture_output=True, text=True, timeout=60)
    print(r.stdout.strip() or "(无输出)")
    if r.stderr.strip():
        print("stderr:", r.stderr.strip()[:500])
