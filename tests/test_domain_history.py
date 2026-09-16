"""域名历史聚合的独立测试：喂合成窗口 → 查 top_domains，验证求和、排序与过滤。"""

from __future__ import annotations

import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import history  # noqa: E402

DB = REPO / "_run" / "repro_domains.db"
for suffix in ("", "-wal", "-shm"):
    target = Path(str(DB) + suffix)
    if target.exists():
        target.unlink()

FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


def window(domains, by_pid=None):
    return {
        "window": 1.0,
        "by_pid": by_pid if by_pid is not None else {100: {"out_bytes": 10, "in_bytes": 10, "packets": 1, "conns": []}},
        "domains": domains,
        "unknown_out": 0,
        "unknown_in": 0,
        "unknown_packets": 0,
        "foreign_bytes_window": 0,
        "foreign_packets_window": 0,
        "skipped_packets_window": 0,
    }


store = history.HistoryStore(DB, flush_interval=0.0)
store.set_name_resolver(lambda pid: f"proc{pid}")
store.open()

store.append(window([
    {"name": "a.example.com", "kind": "sni", "out_bytes": 1000, "in_bytes": 5000, "conns": 2},
    {"name": "b.example.com", "kind": "dns", "out_bytes": 2000, "in_bytes": 1000, "conns": 1},
    {"name": "203.0.113.9", "kind": "ip", "out_bytes": 300, "in_bytes": 300, "conns": 1},
]))
# 同一个域名再来一窗（同一分钟桶内要累计而不是覆盖）
store.append(window([
    {"name": "a.example.com", "kind": "sni", "out_bytes": 1000, "in_bytes": 1000, "conns": 3},
]))
store.append(window([]))       # 空窗口也要能处理
store.close()                  # 定稿并落库

store2 = history.HistoryStore(DB)
store2.open()
rows = store2.top_domains(minutes=60, limit=10)
by_name = {row["name"]: row for row in rows}

check("域名条数（含 IP 桶）", len(rows), 3)
check("同桶累计：a.example.com 总字节（1000+5000+1000+1000）", by_name["a.example.com"]["total_bytes"], 8000)
check("同桶累计：连接数合并", by_name["a.example.com"]["conns"], 5)
check("排序：a 在首位", rows[0]["name"], "a.example.com")
check("来源标注保留", by_name["b.example.com"]["kind"], "dns")

named = store2.top_domains(minutes=60, limit=10, named_only=True)
check("named_only 过滤掉 IP 桶", [row["name"] for row in named], ["a.example.com", "b.example.com"])

# 时间窗口：直接写一行 3 小时前的数据（改库比改时钟干净），60 分钟窗口应排除、240 分钟应包含
import sqlite3  # noqa: E402

raw = sqlite3.connect(DB, timeout=5.0)
raw.execute(
    "INSERT OR REPLACE INTO domains(bucket_ts, name, kind, out_bytes, in_bytes, conns) "
    "VALUES(?, 'old.example.com', 'sni', 999999, 0, 1)",
    (int(time.time()) - 3 * 3600,),
)
raw.commit()
raw.close()

check("60 分钟窗口排除 3 小时前的数据",
      "old.example.com" in {row["name"] for row in store2.top_domains(minutes=60, limit=20)}, False)
check("240 分钟窗口包含它",
      "old.example.com" in {row["name"] for row in store2.top_domains(minutes=240, limit=20)}, True)
stats = store2.stats()
check("stats 里有 domain_rows", stats["domain_rows"] >= 3, True)
store2.close()

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
