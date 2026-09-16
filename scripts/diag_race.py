"""未归因的本地端口到底存在过吗？用 100ms 高频轮询端点表来判别。

- 若在 100ms 轮询里出现过 → socket 存在过、只是没被 1.5s 的刷新抓到（短命连接，刷新频率问题）
- 若从未出现过       → 结构性问题（另一个地址族/地址，或表里就不会有它）

跑法: python diag_race.py [秒数]
"""

from __future__ import annotations

import collections
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collector  # noqa: E402

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 12

poller = collector.WinEndpointTable()
seen: collections.Counter = collections.Counter()
lock = threading.Lock()
stop = threading.Event()
polls = 0


def poll_loop() -> None:
    global polls
    while not stop.is_set():
        try:
            exact, _port_only = poller.fetch()
        except Exception:
            time.sleep(0.2)
            continue
        with lock:
            for key in exact:
                seen[key] += 1
            polls += 1
        time.sleep(0.1)


threading.Thread(target=poll_loop, name="fast-poll", daemon=True).start()

capturer = collector.Capturer()
capturer.start()
local_ips = set(capturer.local_ips)
print(f"设备: {capturer.device_name}")

checks: list[tuple[tuple[str, int], int, bool, int]] = []
t0 = time.monotonic()
while time.monotonic() - t0 < SECONDS:
    time.sleep(1)
    window = capturer.aggregator.flush()
    snapshot = set(capturer.index.exact)
    for flow in window["unknown_flows"]:
        left, _, right = flow["flow"].partition("→")
        for endpoint in (left.strip(), right.strip()):
            ip, _, port = endpoint.rpartition(":")
            if ip in local_ips:
                key = (ip, int(port))
                with lock:
                    hits = seen.get(key, 0)
                checks.append((key, hits, key in snapshot, flow["out_bytes"] + flow["in_bytes"]))
                break

stop.set()
capturer.stop()
with lock:
    poll_cycles = polls

print(f"100ms 轮询执行 {poll_cycles} 次，累计观察到 {len(seen)} 个不同端点")

weighted_total = sum(item[3] for item in checks) or 1
high = [c for c in checks if c[1] > 0]
none = [c for c in checks if c[1] == 0]
print(f"\n未归因的本地端点样本 {len(checks)} 个：")
print(f"  100ms 轮询里出现过: {len(high):>4} 个，占字节 {sum(c[3] for c in high) / weighted_total * 100:5.1f}%"
      f"  ← 属于'短命/漏拍'")
print(f"  从未出现过:         {len(none):>4} 个，占字节 {sum(c[3] for c in none) / weighted_total * 100:5.1f}%"
      f"  ← 属于'结构性看不到'")
print(f"  其中当前 1.5s 快照里就有的: {sum(1 for c in checks if c[2])} 个（应为 0，否则是查询自身有 bug）")

print("\n从未出现过的样例（按字节）:")
for key, hits, _snap, value in sorted(none, key=lambda item: item[3], reverse=True)[:12]:
    print(f"  {value / 1024:8.1f} KiB  {key[0]}:{key[1]}")

print("\n出现过但轮询次数很少（= 生命周期很短）的样例:")
for key, hits, _snap, value in sorted(high, key=lambda item: item[3], reverse=True)[:8]:
    print(f"  {value / 1024:8.1f} KiB  {key[0]}:{key[1]}  命中 {hits}/{poll_cycles} 次轮询")
