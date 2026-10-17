#!/usr/bin/env python3
"""diagnose_resident 第 2 步：崩溃取证 + 实测启动（2026-10-15）。

1. Windows 事件日志里 python.exe 的近期崩溃/错误记录（15:18 前后的死因候选）；
2. 实测启动 server.py（同自启参数 --dev 4FC5DA1D）：起得来吗、健康吗、
   events 表有没有新增写入（采集真的在干活吗），12 秒后停掉。
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "history.db"
LOG = ROOT / "_run" / "probe_server.log"
DEV = "4FC5DA1D"


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def event_log_forensics() -> None:
    print("== Windows 事件日志：python 崩溃记录（近 3 天） ==")
    ps = (
        "Get-WinEvent -FilterHashtable @{LogName='Application'; "
        "StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Message -match 'python|flowwatch' } | "
        "Select-Object -First 15 TimeCreated, ProviderName, @{N='Msg';E={$_.Message.Substring(0,[math]::Min(200,$_.Message.Length))}} | "
        "Format-Table -AutoSize -Wrap | Out-String -Width 200"
    )
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()
    print(out if out else "   （无 python/flowwatch 相关事件）")


def db_max_ts() -> int:
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT MAX(ts) FROM events").fetchone()[0] or 0
    finally:
        conn.close()


def probe_launch() -> None:
    print(f"== 实测启动 server.py --dev {DEV}（12 秒探针） ==")
    before = db_max_ts()
    print(f"   启动前 events MAX(ts) = {fmt(before)}（now={fmt(time.time())}）")
    LOG.write_text("", encoding="utf-8")
    with open(LOG, "a", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [sys.executable, "server.py", "--dev", DEV],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    health = None
    for i in range(10):
        time.sleep(1.5)
        if proc.poll() is not None:
            print(f"   ❌ 进程 {proc.pid} 在 {i*1.5:.0f}s 时退出，exit={proc.returncode}")
            break
        try:
            with urllib.request.urlopen("http://127.0.0.1:8788/api/health", timeout=3) as resp:
                import json
                health = json.loads(resp.read())
                print(f"   ✅ /api/health 200（{i*1.5:.0f}s）")
                break
        except Exception as e:
            if i == 9:
                print(f"   ❌ 12s 内 health 不通：{type(e).__name__}: {e}")
    time.sleep(4)  # 多采几个速率窗口
    alive = proc.poll() is None
    after = db_max_ts()
    print(f"   进程存活: {'是' if alive else '否'} | 采集写入: "
          f"{'有（%s → %s）' % (fmt(before), fmt(after)) if after > before else '无（events 未增长）'}")
    if health:
        keys = ("device", "packets", "unattributed_pct", "uptime", "subscribers")
        brief = {k: health.get(k) for k in keys if k in health}
        print(f"   health: {brief}")
    if alive:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("   已停止探针进程")
    print(f"   探针日志尾部：")
    tail = LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
    for line in tail:
        print(f"   {line}")


if __name__ == "__main__":
    event_log_forensics()
    print()
    probe_launch()
