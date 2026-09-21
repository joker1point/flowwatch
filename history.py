#!/usr/bin/env python3
"""flowwatch / 历史层

产品回答的问题：**「从什么时候开始的」**。

与 portwatch 历史层的区别（同一个判断的两面）：
  - portwatch 留档的是「端口占用」——离散状态，所以是「区间物化表 + 开合事件」；
  - flowwatch 留档的是「速率」——连续量，所以**按时间桶聚合**，绝不逐条落事件/样本。

三条纪律：
  1. **桶内累计、按桶落库**：每分钟每进程一行。写放大 = O(进程数)/分钟，与采样频率无关；
  2. **攒批写**：桶还在跑的时候每 N 秒 upsert 一次（一条事务），桶切完再定稿；
     所以查询能立刻看到"当前这一分钟"，同时不会把每秒的窗口灌进磁盘；
  3. **事件只由真实观测派生**：出现 / 消失 / 尖峰，都是拿已经落库的两个数字比出来的，
     不做任何"推测性"记录 —— 与 portwatch"事件表只允许真实观测追加"是同一条纪律。

哨兵 PID（与采集层同一套语义，负数不是真实进程）：
    -1 属主受限（端点已知、非提权拿不到 owning PID）· -2 本机但未归因
    -3 同网段的邻居流量（广播域里看到的、两端都不是本机）· -4 非 TCP/UDP 或头部不全
只有 pid > 0 参与"进程排行"，但整机总量会把这些桶算进去（它们确实是同一块网卡上看到的量）。
"""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "flowwatch-history/v1"

MASKED_PID = -1
UNATTRIBUTED_PID = -2
FOREIGN_PID = -3
SKIPPED_PID = -4

SENTINEL_NAMES = {
    MASKED_PID: "（属主受限）",
    UNATTRIBUTED_PID: "（未归因）",
    FOREIGN_PID: "（同网段的邻居流量）",
    SKIPPED_PID: "（非 TCP/UDP）",
}

EVENT_KINDS = ("appear", "vanish", "spike")


def now_iso(ts: int | float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time()).isoformat(timespec="seconds")


class HistoryStore:
    """按时间桶聚合的历史层。

    调用方只需每秒把采集层的窗口喂给 `append()`：累计、攒批落库、派生事件都在内部完成。
    """

    def __init__(
        self,
        path: str | Path = "history.db",
        bucket_seconds: int = 60,
        flush_interval: float = 10.0,
        retention_days: float = 30.0,      # 与 server.HISTORY_MAX_DAYS 同义，改一处要改另一处
        event_retention_days: float = 30.0,
        spike_factor: float = 3.0,
        spike_min_bytes: int = 1 << 20,
        appear_min_bytes: int = 256 * 1024,   # "出现"的门槛：低于此值只算噪声，不值得记
        min_baseline: int = 3,                # "尖峰"至少要有这么多个基线桶，否则证据不足
        idle_buckets: int = 3,
    ) -> None:
        self.path = Path(path)
        self.bucket_seconds = bucket_seconds
        self.flush_interval = flush_interval
        self.retention_days = retention_days
        self.event_retention_days = event_retention_days
        self.spike_factor = spike_factor          # 尖峰 = 本桶 ≥ 前 10 桶均值的 K 倍
        self.spike_min_bytes = spike_min_bytes    # 且绝对值够大，避免小流量噪声刷事件
        self.appear_min_bytes = appear_min_bytes
        self.min_baseline = min_baseline
        self._cold_start = True                   # 首次定稿只建基线，不写事件（见 _derive_events）
        self.cold_start_skipped = 0
        self.warm_bucket_rows = 0     # 开库时从当前桶恢复的行数（诊断用）
        self.idle_buckets = idle_buckets          # 连续这么多个空桶才算"消失"
        self.enabled = True                       # --no-history 时置 False（纯实时模式）

        self._conn: sqlite3.Connection | None = None
        self._resolve_name: Any = None
        # 连接可能在不同线程被用到（开库/关库走 asyncio.to_thread，查询在事件循环线程），
        # 所以放开 check_same_thread 并自己串行化：SQLite 允许这样用，只要不并发访问同一个连接。
        self._lock = threading.Lock()
        # 写线程：实时链路只往队列里丢窗口，绝不等待磁盘
        self._queue: queue.Queue | None = None
        self._writer: threading.Thread | None = None
        self._stop_writer = threading.Event()
        self.dropped = 0            # 队列满被丢弃的历史样本数（丢历史，不丢实时）
        self.errors = 0
        self.last_error = ""
    
        self._acc: dict[int, list[int]] = {}          # 当前桶：pid → [out, in, packets]
        self._acc_sentinel: dict[int, list[int]] = {}  # 当前桶：哨兵 pid → [out, in, packets]
        self._domain_acc: dict[tuple[str, str], list[int]] = {}   # 当前桶：(域名, 来源) → [out, in, conns]
        self._bucket_ts: int = 0
        self._last_write = 0.0
        self._recent: dict[int, deque[tuple[int, int]]] = {}   # pid → 近若干桶的 (ts, 总字节)
        self._last_active: dict[int, tuple[int, str]] = {}     # pid → (最后活跃桶, 进程名)
        self._vanish_reported: set[int] = set()
        self.writes = 0
        self.events_written = 0
        self.last_write_ms = 0.0

    # ---------------------------------------------------------------- 生命周期
    def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")        # 读写不互斥：查询不会卡住写入
        conn.execute("PRAGMA synchronous=NORMAL")      # 崩溃最多丢最后一个桶，不值得 fsync 每桶
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS buckets (
              bucket_ts INTEGER NOT NULL,
              pid       INTEGER NOT NULL,
              process   TEXT    NOT NULL,
              out_bytes INTEGER NOT NULL DEFAULT 0,
              in_bytes  INTEGER NOT NULL DEFAULT 0,
              packets   INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (bucket_ts, pid)
            );
            CREATE INDEX IF NOT EXISTS idx_buckets_pid ON buckets(pid, bucket_ts);

            CREATE TABLE IF NOT EXISTS events (
              ts      INTEGER NOT NULL,
              kind    TEXT    NOT NULL,
              pid     INTEGER NOT NULL,
              process TEXT    NOT NULL,
              detail  TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

            CREATE TABLE IF NOT EXISTS domains (
              bucket_ts INTEGER NOT NULL,
              name      TEXT NOT NULL,
              kind      TEXT NOT NULL,          -- sni / dns / ip（未识别时 name 是 IP 字面量）
              out_bytes INTEGER NOT NULL DEFAULT 0,
              in_bytes  INTEGER NOT NULL DEFAULT 0,
              conns     INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (bucket_ts, name, kind)
            );
            CREATE INDEX IF NOT EXISTS idx_domains_name ON domains(name, bucket_ts);

            CREATE TABLE IF NOT EXISTS meta (
              key   TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (SCHEMA,),
        )
        conn.commit()
        self._conn = conn
        self._warm_cache()               # 用库里的近期桶把"已知进程"恢复出来
        self._warm_current_bucket()      # 把当前分钟桶读回来，避免重启覆盖本分钟

    def _bucket_now(self) -> int:
        return int(time.time() // self.bucket_seconds) * self.bucket_seconds

    def _warm_current_bucket(self) -> None:
        """把当前分钟桶已落库的部分读回内存累加器（见模块内 *_commit 的替换语义）。"""
        if self._conn is None:
            return
        bucket = self._bucket_now()
        self._bucket_ts = bucket
        self._acc = {}
        self._acc_sentinel = {}
        self._domain_acc = {}
        rows = self._execute(
            "SELECT pid, out_bytes, in_bytes, packets FROM buckets WHERE bucket_ts = ?", (bucket,)
        ).fetchall()
        for pid, out_bytes, in_bytes, packets in rows:
            target = self._acc if pid > 0 else self._acc_sentinel
            target[pid] = [out_bytes, in_bytes, packets]
        domains = self._execute(
            "SELECT name, kind, out_bytes, in_bytes, conns FROM domains WHERE bucket_ts = ?", (bucket,)
        ).fetchall()
        for name, kind, out_bytes, in_bytes, conns in domains:
            self._domain_acc[(name, kind)] = [out_bytes, in_bytes, conns]
        if rows or domains:
            self.warm_bucket_rows = len(rows) + len(domains)

    def _warm_cache(self) -> None:
        """从库里恢复最近若干桶的观测，喂给 `_recent` / `_last_active`。

        为什么必须做：这两个缓存原来只在内存里，重启后为空 —— 于是重启后第一个定稿的桶
        会把所有在跑的进程都判成"新出现"，刷出一屏假事件。事件只能由**真实变化**触发，
        "我刚重启所以没记住"不是变化。
        """
        if self._conn is None:
            return
        span = max(2, int(600 / self.bucket_seconds))
        cutoff = self._bucket_now() - span * self.bucket_seconds
        rows = self._execute(
            """SELECT pid, process, bucket_ts, out_bytes + in_bytes
               FROM buckets WHERE bucket_ts >= ? AND pid > 0 ORDER BY bucket_ts""",
            (cutoff,),
        ).fetchall()
        for pid, name, stamp, total in rows:
            self._recent.setdefault(pid, deque(maxlen=span)).append((stamp, total))
            self._last_active[pid] = (stamp, name)

    # ---- 语句入口：所有读写都经由这两个方法，锁只在里面
    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        # 这里必须直接用 _conn：写成 self._execute(...) 会自我递归再抢同一把非重入锁，
        # 结果是**同线程永久自锁**（实测：append 正常、stats 直接挂死）。
        with self._lock:
            return self._conn.execute(sql, params)   # type: ignore[union-attr]

    def _write_many(self, sql: str, rows: list[tuple]) -> None:
        with self._lock:
            with self._conn:                              # type: ignore[union-attr]
                self._conn.executemany(sql, rows)         # type: ignore[union-attr]

    # ---------------------------------------------------------------- 写线程
    def start_writer(self) -> None:
        """起独立写线程。之后实时链路只调 submit()（非阻塞）。

        为什么非要隔离：这一层刚出过一次自锁事故 —— 写库卡住时把**整个 API** 冻住了
        （连不碰数据库的 /api/meta 都超时）。历史是增强功能，绝不允许反压实时链路。
        """
        if self._writer is not None or not self.enabled:
            return
        self._queue = queue.Queue(maxsize=16)
        self._writer = threading.Thread(target=self._writer_loop, name="flowwatch-history", daemon=True)
        self._writer.start()

    def submit(self, window: dict[str, Any]) -> None:
        """投递一个窗口给写线程。**非阻塞**：队列满就丢历史样本（历史可以缺，实时不能卡）。"""
        if not self.enabled or self._queue is None:
            self.append(window)          # 没起写线程时退化成同步（单测/脚本场景）
            return
        try:
            self._queue.put_nowait(window)
        except queue.Full:
            self.dropped += 1

    def _writer_loop(self) -> None:
        while True:
            try:
                window = self._queue.get(timeout=0.5)   # type: ignore[union-attr]
            except queue.Empty:
                if self._stop_writer.is_set():
                    return
                continue
            if window is None:
                return
            try:
                self.append(window)
            except Exception as exc:      # 历史写入失败只记账，不影响采集与实时接口
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"

    def stop_writer(self) -> None:
        if self._writer is None:
            return
        self._stop_writer.set()
        try:
            self._queue.put_nowait(None)   # type: ignore[union-attr]
        except queue.Full:
            pass
        self._writer.join(timeout=5.0)
        self._writer = None

    def close(self) -> None:
        self.stop_writer()                   # 先让写线程把队列排空
        if self._conn is None:
            return
        try:
            self._commit(finalize=True)      # 退出时把在跑的桶定稿，别丢最后不到一分钟
        finally:
            self._conn.close()
            self._conn = None

    # ---------------------------------------------------------------- 写入
    def append(self, window: dict[str, Any]) -> bool:
        """把一个速率窗口并进当前时间桶。返回是否发生了落库。"""
        stamp = time.time()
        bucket = int(stamp // self.bucket_seconds) * self.bucket_seconds
        if bucket != self._bucket_ts:
            if self._bucket_ts:              # 上一个桶到此结束：定稿（派生事件 + 清理）
                self._commit(finalize=True)
            self._bucket_ts = bucket
            self._acc = {}
            self._acc_sentinel = {}
            self._domain_acc = {}

        for pid, item in window["by_pid"].items():
            slot = self._acc.get(pid)
            if slot is None:
                slot = self._acc[pid] = [0, 0, 0]
            slot[0] += item["out_bytes"]
            slot[1] += item["in_bytes"]
            slot[2] += item["packets"]

        self._add_sentinel(UNATTRIBUTED_PID, window.get("unknown_out", 0),
                           window.get("unknown_in", 0), window.get("unknown_packets", 0))
        self._add_sentinel(FOREIGN_PID, 0, window.get("foreign_bytes_window", 0),
                           window.get("foreign_packets_window", 0))
        self._add_sentinel(SKIPPED_PID, 0, 0, window.get("skipped_packets_window", 0))

        for entry in window.get("domains", ()):      # 域名维度（采集层已按全部连接汇总）
            key = (entry["name"], entry["kind"])
            slot = self._domain_acc.get(key)
            if slot is None:
                slot = self._domain_acc[key] = [0, 0, 0]
            slot[0] += entry["out_bytes"]
            slot[1] += entry["in_bytes"]
            slot[2] += entry.get("conns", 0)

        if stamp - self._last_write >= self.flush_interval:
            self._commit(finalize=False)
            return True
        return False

    def _add_sentinel(self, pid: int, out_bytes: int, in_bytes: int, packets: int) -> None:
        if not (out_bytes or in_bytes or packets):
            return
        slot = self._acc_sentinel.get(pid)
        if slot is None:
            slot = self._acc_sentinel[pid] = [0, 0, 0]
        slot[0] += out_bytes
        slot[1] += in_bytes
        slot[2] += packets

    def _commit(self, finalize: bool) -> None:
        if self._conn is None or not self._bucket_ts:
            return
        rows = self._rows()
        if not rows:
            self._last_write = time.time()
            return
        started = time.monotonic()
        self._write_many(
            """INSERT INTO buckets(bucket_ts, pid, process, out_bytes, in_bytes, packets)
               VALUES(?, ?, ?, ?, ?, ?)
               ON CONFLICT(bucket_ts, pid) DO UPDATE SET
                 out_bytes = excluded.out_bytes,
                 in_bytes  = excluded.in_bytes,
                 packets   = excluded.packets,
                 process   = excluded.process""",
            rows,
        )
        domain_rows = [
            (self._bucket_ts, name, kind, slot[0], slot[1], slot[2])
            for (name, kind), slot in self._domain_acc.items()
        ]
        if domain_rows:
            self._write_many(
                """INSERT INTO domains(bucket_ts, name, kind, out_bytes, in_bytes, conns)
                   VALUES(?, ?, ?, ?, ?, ?)
                   ON CONFLICT(bucket_ts, name, kind) DO UPDATE SET
                     out_bytes = excluded.out_bytes,
                     in_bytes  = excluded.in_bytes,
                     conns     = excluded.conns""",
                domain_rows,
            )
        self.last_write_ms = (time.monotonic() - started) * 1000
        self.writes += 1
        self._last_write = time.time()
        if finalize:
            self._derive_events(rows)
            self._prune()

    def _rows(self) -> list[tuple[int, int, str, int, int, int]]:
        rows = [
            (self._bucket_ts, pid, self._name(pid), slot[0], slot[1], slot[2])
            for pid, slot in self._acc.items()
        ]
        for pid, slot in self._acc_sentinel.items():
            rows.append((self._bucket_ts, pid, SENTINEL_NAMES.get(pid, "（哨兵）"), slot[0], slot[1], slot[2]))
        return rows

    def _name(self, pid: int) -> str:
        if pid < 0:
            return SENTINEL_NAMES.get(pid, "（哨兵）")
        if self._resolve_name is not None:
            try:
                return str(self._resolve_name(pid))
            except Exception:
                pass
        return f"pid {pid}"

    def set_name_resolver(self, resolver: Any) -> None:
        """注入 pid → 进程名的解析器（服务端的 NameCache）。

        为什么冗余存名字：**pid 会被系统复用**，历史必须自洽 —— 一周后回看，
        那个 pid 早就不是它了，只有当时记下的名字才是真的。
        """
        self._resolve_name = resolver

    # ---------------------------------------------------------------- 事件
    def _derive_events(self, rows: Iterable[tuple[int, int, str, int, int, int]]) -> None:
        """只在**桶定稿**时派生事件：所有比较都发生在两个已观测的数字之间。"""
        buckets = max(2, int(600 / self.bucket_seconds))     # 均值基线窗口 ≈ 10 分钟
        fresh: list[tuple] = []
        seen: set[int] = set()
        cold = self._cold_start
        self._cold_start = False
        for _ts, pid, name, out_bytes, in_bytes, packets in rows:
            if pid <= 0:
                continue
            seen.add(pid)
            total = out_bytes + in_bytes
            if total <= 0:
                continue
            history = self._recent.get(pid)
            if history is None or not history:
                if total >= self.appear_min_bytes:      # 76 B/分钟不配叫"出现"
                    fresh.append((self._bucket_ts, "appear", pid, name,
                                  f"首次观测到流量 {_human(total)}/分钟"))
            else:
                baseline = [value for _stamp, value in history][-buckets:]
                if len(baseline) >= self.min_baseline:  # 证据不足就不下"尖峰"这个判断
                    mean = sum(baseline) / len(baseline)
                    if total >= self.spike_min_bytes and mean > 0 and total >= self.spike_factor * mean:
                        fresh.append((self._bucket_ts, "spike", pid, name,
                                      f"{_human(total)}/分钟，是近 {len(baseline)} 桶均值 {_human(int(mean))} 的 "
                                      f"{total / mean:.1f} 倍"))
            slot = self._recent.setdefault(pid, deque(maxlen=buckets))
            slot.append((self._bucket_ts, total))
            self._last_active[pid] = (self._bucket_ts, name)
            self._vanish_reported.discard(pid)

        # 消失：连续 idle_buckets 个桶没有它的流量才算（避免把"这一分钟没流量"当消失）
        idle_seconds = self.idle_buckets * self.bucket_seconds
        for pid, (last_ts, name) in list(self._last_active.items()):
            if pid in seen or pid in self._vanish_reported:
                continue
            if self._bucket_ts - last_ts >= idle_seconds:
                fresh.append((self._bucket_ts + idle_seconds, "vanish", pid, name,
                              f"连续 {self.idle_buckets} 分钟无流量"))
                self._vanish_reported.add(pid)
                self._recent.pop(pid, None)

        if cold:      # 冷启动：这一轮只建立基线，不写事件
            self.cold_start_skipped += len(fresh)
            return
        if not fresh:
            return
        self._write_many("INSERT INTO events(ts, kind, pid, process, detail) VALUES(?, ?, ?, ?, ?)", fresh)
        self.events_written += len(fresh)

    def _prune(self) -> None:
        if self._conn is None:
            return
        wall = time.time()
        bucket_cutoff = int(wall - self.retention_days * 86400)
        event_cutoff = int(wall - self.event_retention_days * 86400)
        self._execute("DELETE FROM buckets WHERE bucket_ts < ?", (bucket_cutoff,))
        self._execute("DELETE FROM domains WHERE bucket_ts < ?", (bucket_cutoff,))
        self._execute("DELETE FROM events WHERE ts < ?", (event_cutoff,))

    # ---------------------------------------------------------------- 查询
    def _since(self, minutes: int) -> int:
        current = int(time.time() // self.bucket_seconds) * self.bucket_seconds
        return current - max(1, minutes) * 60

    def process_series(self, pid: int, minutes: int = 60, bucket_minutes: int = 1) -> dict[str, Any]:
        """某进程的时间序列（可重采样到 5/15/60 分钟桶）。速率 = 桶内字节 / 桶宽。"""
        if self._conn is None:
            return {}
        span = max(1, bucket_minutes) * 60
        since = self._since(minutes)
        rows = self._execute(
            """SELECT (bucket_ts / ?) * ? AS bucket, SUM(out_bytes), SUM(in_bytes), SUM(packets)
               FROM buckets WHERE pid = ? AND bucket_ts >= ? GROUP BY bucket ORDER BY bucket""",
            (span, span, pid, since),
        ).fetchall()
        series = [
            {
                "ts": now_iso(bucket),
                "out_bps": out / span,
                "in_bps": in_b / span,
                "bytes": out + in_b,
                "packets": packets,
            }
            for bucket, out, in_b, packets in rows
        ]
        total = sum(item["bytes"] for item in series)
        peak = max((item["out_bps"] + item["in_bps"] for item in series), default=0.0)
        name = series and self._execute(
            "SELECT process FROM buckets WHERE pid = ? ORDER BY bucket_ts DESC LIMIT 1", (pid,)
        ).fetchone()
        return {
            "pid": pid,
            "process": (name[0] if name else SENTINEL_NAMES.get(pid, "?")),
            "bucket_seconds": span,
            "since": now_iso(since),
            "first_seen": series[0]["ts"] if series else None,
            "last_seen": series[-1]["ts"] if series else None,
            "total_bytes": total,
            "peak_bps": peak,
            "series": series,
        }

    def top_processes(self, minutes: int = 60, limit: int = 10,
                      match: str | None = None, group: bool = False) -> list[dict[str, Any]]:
        """区间内按累计字节排行的进程（只统计 pid > 0）。

        三种用法，各自解决一类问题：
        - 默认：**按 pid** 排行 —— UI 的进程榜用它做"点进去看曲线"的入口，pid 就是钻取键；
        - `match='doubao'`：按名字片段在**全量数据**里检索，命中结果**按进程名合并**
          （SQLite 的 LIKE 对 ASCII 默认不区分大小写，所以小写 doubao 能命中 Doubao.exe）。
          点名叫一个应用时这是唯一正确查法 —— 去排行榜前 N 条里"扫一眼"会漏。
        - `group=True`：排行本身也按进程名合并。Electron 类应用常跑十几个同名进程，
          按 pid 会被拆成十几行，单个 pid 甚至挤不进榜单。
        """
        if self._conn is None:
            return []
        since = self._since(minutes)
        needle = (match or "").strip()[:60]
        clause = ""
        params: list[Any] = [since]
        if needle:
            clause = " AND EXISTS (SELECT 1 FROM buckets y WHERE y.pid = b.pid AND y.process LIKE ?)"
            params.append(f"%{needle}%")
        merge = bool(needle) or group
        tail = "" if merge else "\n               LIMIT ?"
        sql = f"""SELECT b.pid,
                      (SELECT process FROM buckets x WHERE x.pid = b.pid
                        ORDER BY x.bucket_ts DESC LIMIT 1) AS process,
                      SUM(b.out_bytes + b.in_bytes) AS total,
                      SUM(b.out_bytes), SUM(b.in_bytes),
                      MIN(b.bucket_ts), MAX(b.bucket_ts)
               FROM buckets b
               WHERE b.bucket_ts >= ? AND b.pid > 0{clause}
               GROUP BY b.pid
               ORDER BY total DESC{tail}"""
        rows = self._execute(sql, tuple(params if merge else params + [limit])).fetchall()
        items = [
            {
                "pid": pid,
                "process": name,
                "total_bytes": total,
                "out_bytes": out,
                "in_bytes": in_b,
                "first_seen": now_iso(first),
                "last_seen": now_iso(last),
            }
            for pid, name, total, out, in_b, first, last in rows
        ]
        return self._merge_by_name(items, limit) if merge else items

    @staticmethod
    def _merge_by_name(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        """把按 pid 的行合并成按**进程名**的行。

        `pid` 保留流量最大的那个（仍是钻取入口），其余进 `pids`，并给出 `pid_count`。
        入参必须已按流量降序；合并结果同样按总流量降序后截断。
        """
        merged: dict[str, dict[str, Any]] = {}
        for item in items:
            key = (item.get("process") or "?").casefold()
            row = merged.get(key)
            if row is None:
                merged[key] = {**item, "pids": [item["pid"]], "pid_count": 1}
                continue
            row["total_bytes"] += item["total_bytes"]
            row["out_bytes"] += item["out_bytes"]
            row["in_bytes"] += item["in_bytes"]
            row["pids"].append(item["pid"])
            row["pid_count"] += 1
            row["first_seen"] = min(row["first_seen"], item["first_seen"])
            row["last_seen"] = max(row["last_seen"], item["last_seen"])
        return sorted(merged.values(), key=lambda row: row["total_bytes"], reverse=True)[:limit]

    def timeline(self, minutes: int = 60, bucket_minutes: int = 5) -> dict[str, Any]:
        """整机时间序列：本机已归因 / 属主受限 / 未归因 / 别人的流量 分开给。"""
        if self._conn is None:
            return {}
        span = max(1, bucket_minutes) * 60
        since = self._since(minutes)
        rows = self._execute(
            """SELECT (bucket_ts / ?) * ? AS bucket,
                      SUM(CASE WHEN pid > 0 THEN out_bytes ELSE 0 END),
                      SUM(CASE WHEN pid > 0 THEN in_bytes  ELSE 0 END),
                      SUM(CASE WHEN pid = ? THEN out_bytes ELSE 0 END),
                      SUM(CASE WHEN pid = ? THEN out_bytes + in_bytes ELSE 0 END),
                      SUM(CASE WHEN pid = ? THEN out_bytes + in_bytes ELSE 0 END)
               FROM buckets WHERE bucket_ts >= ? GROUP BY bucket ORDER BY bucket""",
            (span, span, MASKED_PID, UNATTRIBUTED_PID, FOREIGN_PID, since),
        ).fetchall()
        series = [
            {
                "ts": now_iso(bucket),
                "own_out_bps": out / span,
                "own_in_bps": in_b / span,
                "masked_bps": masked / span,
                "unattributed_bps": unattributed / span,
                "foreign_bps": foreign / span,
            }
            for bucket, out, in_b, masked, unattributed, foreign in rows
        ]
        return {"bucket_seconds": span, "since": now_iso(since), "series": series}

    def top_domains(self, minutes: int = 60, limit: int = 20, named_only: bool = False,
                    match: str | None = None) -> list[dict[str, Any]]:
        """区间内的域名排行。`named_only=True` 时排除未识别（kind='ip'）的条目。

        `match` 按名字片段检索（同 top_processes：ASCII 不区分大小写，小写 doubao 能命中
        logifier.doubao.com）。过滤发生在 LIMIT 之前，所以点名声明的域名不会被排行榜截掉。
        """
        if self._conn is None:
            return []
        since = self._since(minutes)
        clause = "AND kind <> 'ip'" if named_only else ""
        params: list[Any] = [since]
        needle = (match or "").strip()[:60]
        if needle:
            clause += " AND name LIKE ?"
            params.append(f"%{needle}%")
        rows = self._execute(
            f"""SELECT name, kind, SUM(out_bytes), SUM(in_bytes), SUM(conns)
                FROM domains WHERE bucket_ts >= ? {clause}
                GROUP BY name, kind
                ORDER BY SUM(out_bytes + in_bytes) DESC
                LIMIT ?""",
            tuple(params + [limit]),
        ).fetchall()
        return [
            {
                "name": name,
                "kind": kind,
                "out_bytes": out,
                "in_bytes": in_b,
                "conns": conns,
                "total_bytes": out + in_b,
            }
            for name, kind, out, in_b, conns in rows
        ]

    def events(self, limit: int = 50, pid: int | None = None,
               match: str | None = None, minutes: int | None = None) -> list[dict[str, Any]]:
        """变化事件流（出现 / 消失 / 尖峰），由落库观测值派生。

        - `pid`：精确定位一个进程实例（pid 每分钟都可能变，问"某个应用"时别用它）；
        - `match`：按**进程名**过滤（不区分大小写子串）—— 这才是"doubao 最近有没有异常"的正路；
        - `minutes`：只看最近多少分钟。事件是稀疏数据，不给窗口时 LIMIT 20 很容易全是别人的事件，
          于是"没查到"变成假结论。
        """
        if self._conn is None:
            return []
        clause = ""
        params: list[Any] = []
        if pid is not None:
            clause += " AND pid = ?"
            params.append(pid)
        needle = (match or "").strip()[:60]
        if needle:
            clause += " AND process LIKE ?"
            params.append(f"%{needle}%")
        if minutes:
            clause += " AND ts >= ?"
            params.append(int(time.time()) - max(1, minutes) * 60)
        params.append(limit)
        rows = self._execute(
            f"SELECT ts, kind, pid, process, detail FROM events WHERE 1=1{clause}"
            " ORDER BY ts DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        return [
            {"ts": now_iso(ts), "kind": kind, "pid": pid_, "process": name, "detail": detail}
            for ts, kind, pid_, name, detail in rows
        ]

    def stats(self) -> dict[str, Any]:
        if self._conn is None:
            return {"enabled": False}
        buckets, events = self._execute(
            "SELECT (SELECT COUNT(*) FROM buckets), (SELECT COUNT(*) FROM events)"
        ).fetchone()
        oldest = self._execute("SELECT MIN(bucket_ts) FROM buckets").fetchone()[0]
        domains = self._execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        return {
            "enabled": True,
            "path": str(self.path),
            "bucket_seconds": self.bucket_seconds,
            "retention_days": self.retention_days,
            "buckets": buckets,
            "events": events,
            "domain_rows": domains,          # 域名桶行数（每桶每域名一行）
            "oldest": now_iso(oldest) if oldest else None,
            "writes": self.writes,
            "events_written": self.events_written,
            "cold_start_skipped": self.cold_start_skipped,
            "queued": self._queue.qsize() if self._queue else 0,
            "dropped": self.dropped,          # 队列满丢弃的历史样本（正常应长期为 0）
            "errors": self.errors,
            "last_error": self.last_error,
            "last_write_ms": round(self.last_write_ms, 2),
            "size_kb": round(self.path.stat().st_size / 1024, 1) if self.path.exists() else 0.0,
        }


def _human(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"
