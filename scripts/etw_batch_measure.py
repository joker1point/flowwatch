"""证据脚本：批量路线可行性测量（XML 体积 / 解析速度 / 信噪比 / 字段完整性）。

先跑 scripts/etw_probe_logman.py 生成 ETL，再用 tracerpt 转成 XML，然后运行本脚本。
"""

from __future__ import annotations

import re
import sys
import time
from collections import Counter
from pathlib import Path

RUN = Path(__file__).resolve().parents[1] / "_run"
XML = RUN / "flowwatch-etl.xml"
NEEDED = {12: "TCPv4 connect", 15: "TCPv4 accept", 28: "TCPv6 connect", 31: "TCPv6 accept",
          13: "TCPv4 disconnect", 29: "TCPv6 disconnect"}

EVENT_ID = re.compile(rb"<EventID>(\d+)</EventID>")
DATA = re.compile(rb'<Data Name="([^"]+)">([^<]*)</Data>')


def main() -> int:
    if not XML.exists():
        print(f"缺少 {XML}（先跑 scripts/etw_probe_logman.py 生成 ETL 再 tracerpt 转 XML）", file=sys.stderr)
        return 1
    size_mb = XML.stat().st_size / 1048576
    started = time.perf_counter()
    raw = XML.read_bytes()
    records = raw.split(b"<Event ")
    histogram: Counter = Counter()
    sample: str | None = None
    needed_with_fields = 0
    for record in records:
        matched = EVENT_ID.search(record)
        if matched is None:
            continue
        event_id = int(matched.group(1))
        histogram[event_id] += 1
        if event_id in NEEDED:
            fields = DATA.findall(record)
            if fields:
                needed_with_fields += 1
                if sample is None:
                    pairs = " · ".join(f"{name.decode()}={value.decode()}" for name, value in fields[:10])
                    sample = f"event {event_id}（{NEEDED[event_id]}）: {pairs}"
    elapsed = time.perf_counter() - started
    total = sum(histogram.values())
    needed = sum(count for event_id, count in histogram.items() if event_id in NEEDED)

    print(f"XML {size_mb:.1f} MB · 事件总数 {total} · 解析耗时 {elapsed:.2f}s（{size_mb / elapsed:.0f} MB/s）")
    print(f"\n我需要的连接事件: {needed} 条（占 {needed / total * 100:.2f}%）· 其中带字段的 {needed_with_fields} 条")
    print("\n事件 ID 分布（前 8）:")
    for event_id, count in histogram.most_common(8):
        label = NEEDED.get(event_id, "")
        print(f"  id={event_id:<4} {count:>7} 条  {label}")
    if sample:
        print("\n字段样例（这是批量路线能不能用的关键）:")
        print("  " + sample)
    print(f"\n判断依据：采集窗口只有 9 秒（8MB ETL），批量路线每秒流量要解析约 "
          f"{size_mb / 9:.0f} MB XML、转换约 230 ms —— 对比 1 秒的速率窗口，"
          f"{'不可行' if size_mb / 9 > 3 else '可行'}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
