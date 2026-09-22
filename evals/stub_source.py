"""评估集用的固定"世界"：假历史层 / 假实时帧 / 假采集层。

与 `tests/test_assistant.py` 里的 FakeStore/FakeHub/FakeCapturer **同形、同数值** ——
单元测试刻意自包含（不依赖测试以外的模块），评估集则要一份"可复现的世界"来做行为断言，
所以这里保留一份；**改任一边的字段形状时，两边一起改**（形状不一致会让评估与单测各说各话）。

数值刻意与单测一致，便于对照：
  · Steam++.Accelerator.exe #84812 ≈ 1018 MiB（榜首）
  · Doubao.exe 两个 pid（#50164 / #50304）—— 模拟 Electron 一个应用多进程
  · 域名里同时有 IP 字面量（10.44.99.5）与 SNI（logifier.doubao.com）
"""
from __future__ import annotations


def _proc_row(pid: int, process: str, total: int) -> dict:
    return {
        "pid": pid, "process": process, "total_bytes": total,
        "out_bytes": total * 9 // 10, "in_bytes": total // 10,
        "first_seen": "2026-09-19T08:45:00", "last_seen": "2026-09-19T11:30:00",
    }


class FakeStore:
    """假历史层。

    **刻意保留真 `HistoryStore` 上的写方法**（且一调就炸）：只读门面要挡的就是它们 ——
    桩里没有写方法的话，"门面被绕过（助手重新拿到可写库）"这类回退根本测不出来。
    """

    # ---- 写面：与 history.HistoryStore 同形，只为让"只读门面"可被证伪 ----
    def _deny(self, name: str):
        raise AssertionError(f"助手不该能调历史库的写方法 {name}（只读门面被绕过了）")

    def open(self) -> None:
        self._deny("open")

    def append(self, window: dict) -> bool:
        self._deny("append")

    def submit(self, window: dict) -> None:
        self._deny("submit")

    def start_writer(self) -> None:
        self._deny("start_writer")

    def stop_writer(self) -> None:
        self._deny("stop_writer")

    def close(self) -> None:
        self._deny("close")

    def set_name_resolver(self, resolver) -> None:
        self._deny("set_name_resolver")

    # ---- 读面：工具真正会用的 ----
    def stats(self) -> dict:
        return {"retention_days": 30, "oldest": "2026-09-17T08:00:00", "buckets": 11, "events": 3}

    def top_processes(self, minutes: int = 60, limit: int = 10,
                      match: str | None = None, group: bool = False) -> list[dict]:
        rows = [_proc_row(84812, "Steam++.Accelerator.exe", 1067797993),
                _proc_row(50164, "Doubao.exe", 14093555),
                _proc_row(50304, "Doubao.exe", 6318897)]
        if match:
            return [row for row in rows if match.lower() in row["process"].lower()][:limit]
        if not group:
            return rows[:limit]
        merged: dict[str, dict] = {}
        for row in rows:
            key = row["process"].lower()
            if key in merged:
                merged[key]["total_bytes"] += row["total_bytes"]
                merged[key]["pid_count"] += 1
            else:
                merged[key] = {**row, "pid_count": 1}
        return sorted(merged.values(), key=lambda item: item["total_bytes"], reverse=True)[:limit]

    def top_domains(self, minutes: int = 60, limit: int = 10, named_only: bool = False,
                    match: str | None = None) -> list[dict]:
        rows = [{"name": "10.44.99.5", "kind": "ip", "total_bytes": 976000000, "conns": 79275},
                {"name": "logifier.doubao.com", "kind": "sni", "total_bytes": 23051911, "conns": 42}]
        if match:
            rows = [row for row in rows if match.lower() in row["name"].lower()]
        return rows[:limit]

    def process_series(self, pid: int, minutes: int = 60, bucket_minutes: int = 1) -> dict:
        if pid != 84812:
            return {}
        return {
            "pid": pid, "process": "Steam++.Accelerator.exe",
            "bucket_seconds": bucket_minutes * 60, "total_bytes": 1067797993, "peak_bps": 303453,
            "first_seen": "2026-09-19T08:45:00", "last_seen": "2026-09-19T11:30:00",
            "series": [{"ts": f"2026-09-19T{8 + i // 4:02d}:{(i % 4) * 15:02d}:00",
                        "out_bps": 1000.0 * i, "in_bps": 100.0, "bytes": 0, "packets": 0}
                       for i in range(12)],
        }

    def events(self, limit: int = 20, pid: int | None = None,
               match: str | None = None, minutes: int | None = None) -> list[dict]:
        items = [{"ts": "2026-09-20T09:53:00", "kind": "vanish", "pid": 50164,
                  "process": "Doubao.exe", "detail": "连续 3 分钟无流量"},
                 {"ts": "2026-09-19T11:12:00", "kind": "vanish", "pid": 84812,
                  "process": "Steam++.Accelerator.exe", "detail": "连续 3 分钟无流量"}]
        if pid is not None:
            items = [item for item in items if item["pid"] == pid]
        if match:
            items = [item for item in items if match.lower() in item["process"].lower()]
        return items[:limit]


class FakeHub:
    latest = {
        "ts": "2026-09-19T11:32:01", "window": 1.0,
        "totals": {"out_bps": 131518.0, "in_bps": 1702.0, "unknown_ratio_rolling": 0.01,
                   "unknown_ratio": 0.0, "masked_bytes": 0, "foreign_packets": 0,
                   "skipped_packets": 0, "packets": 10, "bytes": 1000, "packets_window": 10,
                   "unknown_bytes_window": 0, "masked_ratio_rolling": 0.0, "rolling_windows": 60},
        "domains": [{"name": "10.44.99.5", "kind": "ip", "out_bytes": 900, "in_bytes": 10, "conns": 3}],
        "unknown_flows": [],
        "by_pid": [
            {"pid": 84812, "process": "Steam++.Accelerator.exe", "out_bps": 900.0, "in_bps": 100.0,
             "packets": 10,
             "conns": [{"remote": "10.44.99.5:49716", "name": None, "name_source": None,
                        "out_bps": 800.0, "in_bps": 0.0}]}
        ],
    }


class FakeCapturer:
    device_name = "\\Device\\NPF_TEST"
    error = None
    refresh_error = None
    aggregator = type("Agg", (), {"stats": staticmethod(lambda: {"packets": 12345678})})()
    resolver = type("Res", (), {"stats": staticmethod(
        lambda: {"dns_records": 100, "sni_records": 50, "hit_ratio": 0.38})})()

    @staticmethod
    def watchdog_stats() -> dict:
        return {"reopen_count": 0, "last_reopen_error": None, "stale_seconds": 180}
