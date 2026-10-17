#!/usr/bin/env python3
"""diagnose_resident 第 3 步：采集生死的权威读数 + 探针 v2（2026-10-15）。

修正探针 v1 的两个缺陷：
  · events 是离散事件表 → 改看 buckets(bucket_ts)（速率桶，采集活着就会每分钟写）；
  · health 的 device='' 是选网卡还在后台跑 → 轮询到 status=='ok' 再读数，
    并直接读 /api/rates 验证抓包真的有字节（不用等一个桶周期才确认）。
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "history.db"
LOG = ROOT / "_run" / "probe_server2.log"
DEV = "4FC5DA1D"


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def q(sql):
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        return conn.execute(sql).fetchone()
    finally:
        conn.close()


def bucket_status(tag):
    for t in ("buckets", "conn_buckets", "domains"):
        row = q(f"SELECT MAX(bucket_ts), COUNT(*) FROM {t}")
        print(f"   [{tag}] {t}: MAX(bucket_ts)={fmt(row[0])}  行数={row[1]}")


def get(path, timeout=5):
    with urllib.request.urlopen(f"http://127.0.0.1:8788{path}", timeout=timeout) as r:
        return json.loads(r.read())


if __name__ == "__main__":
    print("== 采集停止时间（buckets 权威读数） ==")
    bucket_status("探针前")
    print(f"   now = {fmt(time.time())}")

    print(f"\n== 探针 v2：启动 → 等 status=ok → 读 rates → 等一个桶周期 ==")
    LOG.write_text("", encoding="utf-8")
    with open(LOG, "a", encoding="utf-8") as log:
        proc = subprocess.Popen([sys.executable, "server.py", "--dev", DEV],
                                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    try:
        ok = False
        for i in range(12):
            time.sleep(1.5)
            try:
                h = get("/api/health", timeout=3)
            except Exception as e:
                print(f"   {i*1.5:4.0f}s health 异常: {type(e).__name__}")
                continue
            print(f"   {i*1.5:4.0f}s status={h.get('status')} device={str(h.get('device'))[:30]!r} "
                  f"packets={h.get('packets')} bytes={h.get('bytes')} err={h.get('error')}")
            if h.get("status") == "ok":
                ok = True
                break
        if not ok:
            print("   ❌ 18s 内未到 status=ok")
        else:
            rates = get("/api/rates", timeout=5)
            procs = rates.get("processes") or rates
            print(f"   rates: {len(procs) if isinstance(procs, list) else procs} 个进程有速率数据")
            if isinstance(procs, list) and procs:
                top = sorted(procs, key=lambda p: p.get("bytes_per_sec", 0), reverse=True)[:3]
                for p in top:
                    print(f"     {p.get('process','?')[:30]:30s} {p.get('bytes_per_sec',0)/1024:8.1f} KiB/s")
            before = q("SELECT MAX(bucket_ts) FROM buckets")[0] or 0
            print(f"   等待一个桶周期（65s）验证落库…")
            time.sleep(65)
            after = q("SELECT MAX(bucket_ts) FROM buckets")[0] or 0
            grew = after > before
            print(f"   buckets: {fmt(before)} → {fmt(after)}  {'✅ 采集在写库' if grew else '❌ 未增长'}")
            bucket_status("探针后")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print("   探针进程已停止")
