"""为什么查不到 PID？给 EndpointIndex.pid_of 插桩，统计未命中的**原因分布**。

跑法: python diag_miss.py [秒数]
"""

from __future__ import annotations

import collections
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collector  # noqa: E402

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 15

reasons: collections.Counter = collections.Counter()
samples: dict[str, list[str]] = collections.defaultdict(list)
orig = collector.EndpointIndex.pid_of


def patched(self, ip: str, port: int):  # type: ignore[no-untyped-def]
    pid = orig(self, ip, port)
    if pid is not None:
        reasons["命中"] += 1
        return pid
    if (ip, port) in self.exact:
        kind = "exact 里有但取不到（不该发生）"
    elif port in self.port_only:
        kind = "port_only 里有但取不到（不该发生）"
    elif any(key[1] == port for key in self.exact):
        kind = "同一端口在表里、但 IP 不同（多网卡/绑定地址不一致）"
    elif port in self.port_only or any(p == port for p in self.port_only):
        kind = "通配条目里有同端口"
    elif pid == 0:
        kind = "PID 0"
    else:
        kind = "表里完全没有这个端口（socket 已关 / 从未被看到）"
    reasons[kind] += 1
    if len(samples[kind]) < 4:
        samples[kind].append(f"{ip}:{port}")
    return pid


collector.EndpointIndex.pid_of = patched  # type: ignore[assignment]

capturer = collector.Capturer()
capturer.start()
print(f"设备: {capturer.device_name}")
print(f"本机地址: {sorted(capturer.local_ips)}")
print(f"端点表: {len(capturer.index.exact)} exact + {len(capturer.index.port_only)} port_only")
pid0 = sum(1 for pid in capturer.index.exact.values() if pid == 0)
print(f"其中 owning PID = 0 的条目: {pid0}（非提权调用常见：拿不到别人进程的 PID）")

t0 = time.monotonic()
while time.monotonic() - t0 < SECONDS:
    time.sleep(1)
capturer.stop()

print(f"\n=== miss 原因分布（{SECONDS}s）===")
total = sum(reasons.values())
for kind, count in reasons.most_common():
    share = count / total * 100 if total else 0
    print(f"{count:>7}  {share:>5.1f}%  {kind}")
    for sample in samples[kind][:3]:
        print(f"          例: {sample}")
print(f"\n本机地址中的 10.44 段: {[ip for ip in sorted(capturer.local_ips) if ip.startswith('10.44')]}")
