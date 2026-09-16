"""未归因率探针：每秒拉一次 /api/rates，打印每个窗口的未归因比例与头部进程。

用法: python unknown_probe.py [秒数] [URL]
"""

from __future__ import annotations

import json
import statistics
import sys
import time
import urllib.request

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 12
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8788"


def fetch() -> dict:
    with urllib.request.urlopen(f"{BASE}/api/rates?limit=5", timeout=5) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    ratios: list[float] = []
    print(f"{'时间':<10} {'未归因':>7} {'发送':>12} {'接收':>12} {'包数':>7}  头部进程")
    for _ in range(SECONDS):
        try:
            frame = fetch()
        except Exception as exc:
            print(f"  拉取失败: {exc}")
            time.sleep(1)
            continue
        totals = frame["totals"]
        ratio = totals.get("unknown_ratio", 0.0)
        ratios.append(ratio)
        top = frame["by_pid"][:2]
        names = " ".join(f"{r['process'][:14]}({(r['out_bps'] + r['in_bps']) / 1024:.0f}K)" for r in top)
        print(
            f"{frame['ts'][11:]:<10} {ratio * 100:>6.1f}% "
            f"{totals.get('out_bps', 0) / 1024:>9.1f}K/s {totals.get('in_bps', 0) / 1024:>9.1f}K/s "
            f"{totals.get('packets_window', 0):>7}  {names}"
        )
        time.sleep(1)

    if ratios:
        print(
            f"\n未归因率: 均值 {statistics.mean(ratios) * 100:.1f}% / 中位 {statistics.median(ratios) * 100:.1f}% / "
            f"最大 {max(ratios) * 100:.1f}% / 最小 {min(ratios) * 100:.1f}%（{len(ratios)} 个窗口）"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
