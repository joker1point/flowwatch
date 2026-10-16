#!/usr/bin/env python3
"""查 events 表里的 gap 事件与最近数据时间线（resident 守护验收用）。"""
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "history.db"
conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
print("最近 6 条 events：")
for ts, kind, pid, process, detail in conn.execute(
    "SELECT ts, kind, pid, process, detail FROM events ORDER BY ts DESC LIMIT 6"
):
    print(f"  {datetime.fromtimestamp(ts):%Y-%m-%d %H:%M:%S}  {kind:8s} pid={pid} {process}  {detail[:80]}")
row = conn.execute("SELECT MAX(bucket_ts) FROM buckets").fetchone()
last = row[0] if row else None
now = int(time.time())
print(f"\nbuckets 最后桶: {datetime.fromtimestamp(last):%Y-%m-%d %H:%M:%S}（{now - last}s 前）" if last else "无桶")
gaps = conn.execute("SELECT COUNT(*) FROM events WHERE kind='gap'").fetchone()[0]
print(f"gap 事件总数: {gaps}")
