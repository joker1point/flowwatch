"""历史层独立复现：不进服务、不连采集层，只喂合成窗口，看每一步是否返回。

用法: python repro_history.py [步骤]   # 默认全跑
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import history  # noqa: E402

DB = REPO / "_run" / "repro.db"
for suffix in ("", "-wal", "-shm"):
    target = Path(str(DB) + suffix)
    if target.exists():
        target.unlink()

WINDOW = {
    "by_pid": {1234: {"out_bytes": 1000, "in_bytes": 2000, "packets": 4}},
    "unknown_out": 10,
    "unknown_in": 5,
    "unknown_packets": 1,
    "foreign_bytes_window": 7,
    "foreign_packets_window": 2,
    "skipped_packets_window": 3,
}


def step(label: str, fn):
    started = time.monotonic()
    try:
        result = fn()
    except Exception as exc:
        print(f"[{label}] 异常 {type(exc).__name__}: {exc}", flush=True)
        return None
    print(f"[{label}] {time.monotonic() - started:.3f}s → {str(result)[:160]}", flush=True)
    return result


def main() -> int:
    store = history.HistoryStore(DB, flush_interval=0.05, spike_min_bytes=1)
    store.set_name_resolver(lambda pid: f"proc{pid}")
    step("open", store.open)
    step("append#1", lambda: store.append(WINDOW))
    step("append#2", lambda: store.append(WINDOW))
    step("stats", store.stats)
    step("timeline", lambda: store.timeline(30, 1))
    step("process_series", lambda: store.process_series(1234, 30, 1))
    step("top", lambda: store.top_processes(30, 5))
    step("events", lambda: store.events(5))
    step("close", store.close)
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
