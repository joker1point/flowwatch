#!/usr/bin/env python3
"""resident_guard —— flowwatch 常驻采集的「进程级」守护（2026-10-15）。

**为什么需要它**（诊断实录）：collector 内部只有线程级看门狗（抓包静默失效会自愈），
但**整个进程死亡无人接管**——10-15 实测采集进程在 15:18~17:01 间静默死亡，
无崩溃转储、非内存守护击杀、无任何日志，采集断裂近 2 小时无人知晓。
本守护按 E-13 配方注册计划任务（心跳 5 分钟 + IgnoreNew），每轮：

  1. 探活：psutil 找 server.py 进程 + HTTP 校验 /api/health（**校验响应体特征**，
     不只看 200——同端口被别的程序占也会回 200，M-39）；
  2. 不活 → 先往 history.db 写一条 kind='gap' 事件（断档时长 = now - 库里最后桶），
     再通过 resident.cmd 拉起（日志落 _run/resident.log，E-24）；
  3. 健康 → no-op。

**用法**:
    python resident_guard.py --once       # 单轮：探活（不活则拉起）——计划任务动作
    python resident_guard.py --install    # 注册计划任务 flowwatch-resident-guard
    python resident_guard.py --uninstall  # 注销计划任务
    python resident_guard.py --status     # 计划任务状态 + 探活结果
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "history.db"
RESIDENT_CMD = ROOT / "resident.cmd"
HEALTH_URL = "http://127.0.0.1:8788/api/health"
TASK_NAME = "flowwatch-resident-guard"
DEV_HINT = "4FC5DA1D"          # 与自启键一致的网卡片段（探测不到本机在跑的历史命令时的兜底）


def find_server_process() -> int | None:
    """找 flowwatch server.py 进程的 pid（psutil 拿 cmdline，不用 Get-Process——
    它没有 CommandLine 属性，M-24）。"""
    if psutil is None:
        return None
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = proc.info.get("cmdline") or []
        except Exception:
            continue
        if not cmdline:
            continue
        joined = " ".join(cmdline)
        if "server.py" in joined and str(ROOT) in joined:
            return proc.info["pid"]
    return None


def health_ok() -> bool:
    """/api/health 200 且响应体带 status 字段（结构校验，不只看状态码——M-39）。"""
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=5) as resp:
            if resp.status != 200:
                return False
            data = json.loads(resp.read(65536).decode("utf-8", "replace"))
            return isinstance(data, dict) and "status" in data
    except Exception:
        return False


def last_bucket_ts() -> int | None:
    if not DB.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT MAX(bucket_ts) FROM buckets").fetchone()
            return int(row[0]) if row and row[0] else None
        finally:
            conn.close()
    except Exception:
        return None


def write_gap_event(now: float, reason: str) -> None:
    """断档事件进 events 表（kind='gap'）：时间线上的缺口诚实可见，
    历史查询/事件流都能看到「这段没采到」，不把断线伪装成连续。"""
    if not DB.exists():
        return
    last = last_bucket_ts()
    gap_min = round((now - last) / 60) if last else None
    detail = reason if gap_min is None else f"{reason}（距最后数据约 {gap_min} 分钟）"
    try:
        conn = sqlite3.connect(DB, timeout=5.0)
        try:
            conn.execute(
                "INSERT INTO events (ts, kind, pid, process, detail) VALUES (?,?,?,?,?)",
                (int(now), "gap", 0, "flowwatch-resident", detail),
            )
            conn.commit()
        finally:
            conn.close()
        print(f"   已写 gap 事件：{detail}")
    except Exception as exc:
        print(f"   gap 事件写入失败（不阻断拉起）：{type(exc).__name__}: {exc}")


def launch() -> bool:
    """通过 resident.cmd 拉起（日志重定向随之生效）；启动器缺失则退回裸命令 + 重定向。"""
    if RESIDENT_CMD.exists():
        subprocess.Popen(["cmd", "/c", str(RESIDENT_CMD)],
                         cwd=ROOT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        return True
    # 兜底：直接起 python，输出拼到 resident.log（不静默死亡优先于姿势优美）
    log = ROOT / "_run" / "resident.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as fh:
        subprocess.Popen([sys.executable, str(ROOT / "server.py"), "--dev", DEV_HINT],
                         cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT)
    return True


def probe() -> dict:
    """探活：**health 响应体校验通过即判健康**（端口 + JSON 特征双校验，M-39）。

    不强制「找到 server.py 进程」：单端口交付形态（run.py）下进程名是 run.py，
    找不到 server.py 也不该误判死亡去重拉（会撞端口）。pid 仅作展示。
    """
    pid = find_server_process()
    healthy = health_ok()
    return {"pid": pid, "health": healthy, "ok": healthy}


def check_once(verbose: bool = True) -> bool:
    """单轮守护。返回「本轮是否健康」（不健康则已尝试拉起）。"""
    st = probe()
    if st["ok"]:
        if verbose:
            print(f"健康：/api/health 200（响应体校验通过，server.py pid={st['pid']}）")
        return True
    why = ["health 异常（进程不在或已僵死）"]
    print(f"不健康：{'；'.join(why)} → 写 gap 事件并拉起")
    write_gap_event(time.time(), "采集进程死亡/无响应，resident_guard 自动拉起")
    launch()
    # 给启动一点时间再复核一次，让计划任务日志能直接看出「拉起是否生效」
    time.sleep(3)
    st2 = probe()
    print(f"   拉起后复核：{'✅ 已恢复' if st2['ok'] else '⚠️ 未恢复（下次心跳再试；查 _run/resident.log）'}")
    return st2["ok"]


# ---------------------------------------------------------------- 计划任务（E-13 配方）

def _ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-Command", script],
                          capture_output=True, text=True, timeout=120)


def install() -> int:
    """注册守护计划任务：心跳 5 分钟（省略 RepetitionDuration=无限）+ 登录触发器 +
    IgnoreNew + 永不超时 + 电池不停 + 重启 999 次。**不传 -Principal**（非提权直接拒绝，E-13）。"""
    action = f'New-ScheduledTaskAction -Execute "{sys.executable}" -Argument ' \
             f'"{ROOT / "scripts" / "resident_guard.py"} --once" -WorkingDirectory "{ROOT}"'
    trigger_hb = ('New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) '
                  '-RepetitionInterval (New-TimeSpan -Minutes 5)')
    trigger_logon = 'New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME'
    settings = ('New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) '
                '-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries '
                '-RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) '
                '-MultipleInstances IgnoreNew')
    script = (
        f"$ErrorActionPreference = 'Stop'; "
        f"$a = {action}; $t1 = {trigger_hb}; $t2 = {trigger_logon}; $s = {settings}; "
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t1,$t2 "
        f"-Settings $s -Force -ErrorAction Stop | Out-Null; "
        f"$t = Get-ScheduledTask -TaskName '{TASK_NAME}'; "
        f"Write-Output ('State=' + $t.State); "
        f"$i = Get-ScheduledTaskInfo -TaskName '{TASK_NAME}'; "
        f"Write-Output ('NextRunTime=' + $i.NextRunTime)"
    )
    r = _ps(script)
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0:
        print(f"注册失败：{err or out or r.returncode}")
        return 1
    print(f"已注册计划任务 {TASK_NAME}：")
    for line in out.splitlines():
        print(f"   {line}")
    print("（心跳 5 分钟；活着时 IgnoreNew 忽略；死后 ≤5 分钟自动拉起；登录时也触发）")
    return 0


def uninstall() -> int:
    r = _ps(f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction SilentlyContinue")
    exists = _ps(f"(Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue) -ne $null").stdout.strip()
    print(f"计划任务 {TASK_NAME}：{'已注销' if exists.lower() != 'true' else '⚠️ 仍存在'}")
    return 0


def status() -> int:
    st = probe()
    print(f"探活：{'✅ 健康' if st['ok'] else '❌ 不健康'}（pid={st['pid']}, health={st['health']}）")
    r = _ps(f"$t = Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue; "
            f"if ($t) {{ $i = Get-ScheduledTaskInfo -TaskName '{TASK_NAME}'; "
            f"Write-Output ('State=' + $t.State); Write-Output ('LastRun=' + $i.LastRunTime); "
            f"Write-Output ('LastResult=' + $i.LastTaskResult); Write-Output ('NextRun=' + $i.NextRunTime) }} "
            f"else {{ Write-Output 'NOT-REGISTERED' }}")
    print(f"计划任务 {TASK_NAME}：")
    for line in (r.stdout or "").strip().splitlines():
        print(f"   {line}")
    print("（LastResult=0x800710E0 = 心跳被 IgnoreNew 忽略，属正常值，E-13）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="flowwatch resident 采集守护（进程级自愈）")
    ap.add_argument("--once", action="store_true", help="单轮探活（不活则拉起）——计划任务动作")
    ap.add_argument("--install", action="store_true", help="注册计划任务")
    ap.add_argument("--uninstall", action="store_true", help="注销计划任务")
    ap.add_argument("--status", action="store_true", help="查看状态")
    args = ap.parse_args()
    if args.install:
        return install()
    if args.uninstall:
        return uninstall()
    if args.status:
        return status()
    return 0 if check_once() else 1


if __name__ == "__main__":
    raise SystemExit(main())
