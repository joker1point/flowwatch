#!/usr/bin/env python3
"""diagnose resident 采集为什么没在跑（一次性诊断，2026-10-15）。

回答三个问题：
  1. history.db 最后一条数据是什么时候（采集实际停止时间，比文件 mtime 准——
     patrol 只读不改 mtime，但查库内容是权威读数）；
  2. 采集进程相关文件（_run/*.etl 等）的时间线；
  3. 内存守护（memory-guard）告警文件里有没有杀 flowwatch 的记录
     （元原则 15：进程静默消失，第一个取证对象是守护日志，不是应用日志）。

用法: python diagnose_resident.py
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "history.db"
RUN_DIR = ROOT / "_run"
ALERT = Path.home() / "Desktop" / "memory-guard-alert.txt"


def fmt(ts: float | int | None) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def db_last_records() -> None:
    print("== history.db 最后记录 ==")
    if not DB.exists():
        print(f"   数据库不存在: {DB}")
        return
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        print(f"   表: {tables}")
        for t in tables:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]
            ts_col = next((c for c in cols if c in ("ts", "ts_sec", "minute", "bucket")), None)
            if not ts_col:
                cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                print(f"   {t}: {cnt} 行（无时间列，跳过）")
                continue
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            lo, hi = conn.execute(f"SELECT MIN({ts_col}), MAX({ts_col}) FROM {t}").fetchone()
            # 时间列可能是 epoch 秒或 epoch 分——先按秒解释，超出合理范围再按分
            def norm(v):
                return v / 60 if v and v > 4e9 else v
            print(f"   {t}: {n} 行 | {fmt(norm(lo))} ~ {fmt(norm(hi))} | 列={cols}")
    finally:
        conn.close()


def run_files() -> None:
    print("== _run 目录时间线（采集副产物） ==")
    if not RUN_DIR.exists():
        print("   _run 不存在")
        return
    for f in sorted(RUN_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:10]:
        st = f.stat()
        print(f"   {fmt(st.st_mtime)}  {st.st_size / 1e6:8.2f} MB  {f.name}")


def guard_alerts() -> None:
    print("== 内存守护告警（memory-guard-alert.txt 尾部） ==")
    if not ALERT.exists():
        print("   无告警文件（守护未记录过击杀，或告警机制未启用）")
        return
    lines = ALERT.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-25:]:
        print(f"   {line}")
    hits = [l for l in lines if "flowwatch" in l.lower() or "python" in l.lower()]
    if hits:
        print(f"   ⚠️ 命中 flowwatch/python 的告警行: {len(hits)} 条（见上）")
    else:
        print("   （无 flowwatch/python 相关告警行）")


if __name__ == "__main__":
    db_last_records()
    print()
    run_files()
    print()
    guard_alerts()
