#!/usr/bin/env python3
"""flowwatch / ETW 归因层（批量路线）

**为什么是批量而不是实时消费**：`etw.py` 里那条 `OpenTraceW` + `ProcessTrace` 的实时路线
在六轮提权实验后被判定未打通（细节与证据见 `etw.py` 头部与 README《ETW 归因》）。
而同一批实验也证明了数据源与权限完全正常 —— 用系统自带 `logman` 采同一 provider，
9 秒得到 73981 条 Kernel-Network 事件。所以这里走**已被证明可用**的路线：

    logman start <会话> -p Microsoft-Windows-Kernel-Network 0x30 4 -o <etl> -ets
      → 等 <窗口> 秒
    logman stop <会话> -ets
      → tracerpt <etl> -o <xml> -of XML -y
      → 解析 XML，取 connect/accept/disconnect 三类事件 → 喂 ConnMemory

实测代价（本机 9 秒、有真实流量时）：ETL 8.1 MB → XML 105.9 MB、tracerpt 2.05 秒；
但**XML 解析只要 0.28 秒（377 MB/s）**，且只关心 0.58% 的连接事件。
因此设计成：**opt-in + 默认 3 秒窗口 + 临时文件每轮删除 + 独立线程**，
任何失败只记账（fail-closed），绝不影响采集与实时链路。

字段语义与 `etw.py` 完全一致（`PID / daddr / saddr / dport / sport`，官方清单顺序），
而且已被真实 dump 印证：`PID=112368 · size=0 · daddr=127.0.0.1 · saddr=127.0.0.1 · dport=7890 · sport=63098`。
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import etw

PROVIDER = "Microsoft-Windows-Kernel-Network"
KEYWORDS = "0x30"            # IPv4 + IPv6
LEVEL = "4"                  # Informational
SESSION = "flowwatch-etw-batch"

EVENT_ID = re.compile(rb"<EventID>(\d+)</EventID>")
DATA = re.compile(rb'<Data Name="([^"]+)">([^<]*)</Data>')
# 需要的事件 → (地址字节数, 是"学到"还是"忘掉")
LEARN = {12: 4, 15: 4, 28: 16, 31: 16}
FORGET = {13: 4, 29: 16}
NEEDED = {**{key: "learn" for key in LEARN}, **{key: "forget" for key in FORGET}}


def parse_dump(xml: bytes) -> list[dict[str, Any]]:
    """从 tracerpt 的 XML dump 里抽出连接事件（纯函数，可单测）。

    只认 connect/accept/disconnect；send/recv（占总量的 99% 以上）直接跳过。
    字段取自 `<Data Name="X">Y</Data>`；缺字段或明显非法的一律丢弃 —— **宁可不归因，也不误归因**。
    """
    events: list[dict[str, Any]] = []
    for record in xml.split(b"<Event "):
        matched = EVENT_ID.search(record)
        if matched is None:
            continue
        event_id = int(matched.group(1))
        kind = NEEDED.get(event_id)
        if kind is None:
            continue
        fields = {name.decode(): value.decode().strip() for name, value in DATA.findall(record)}
        try:
            pid = int(fields.get("PID", "").strip() or 0)
            sport = int(fields.get("sport", "").strip() or 0)
            dport = int(fields.get("dport", "").strip() or 0)
        except ValueError:
            continue
        saddr = fields.get("saddr", "").strip().lower()
        daddr = fields.get("daddr", "").strip().lower()
        if pid <= 0 or pid > 0x7FFFFFFF or not (0 < sport <= 65535) or not saddr or not daddr:
            continue
        events.append({"event_id": event_id, "kind": kind, "pid": pid,
                       "saddr": saddr, "sport": sport, "daddr": daddr, "dport": dport})
    return events


class EtwBatchTracker:
    """批量路线：logman 采 ETL → tracerpt 转 XML → 解析 → 喂 ConnMemory。"""

    def __init__(self, conn_memory: Any, local_ips_provider: Any,
                 window: float = 3.0, run_dir: Path | None = None,
                 provider: str = PROVIDER, session: str = SESSION) -> None:
        self.conn_memory = conn_memory
        self.local_ips_provider = local_ips_provider
        self.window = window
        self.provider = provider
        self.session = session
        self.run_dir = Path(run_dir) if run_dir else Path(__file__).resolve().parent / "_run"
        self.state = "idle"          # idle / denied / running / failed / stopped
        self.detail = ""
        self.rounds = 0
        self.events = 0
        self.learned = 0
        self.forgotten = 0
        self.sanity_failures = 0
        self.errors = 0
        self.last_round_ms = 0.0
        self.last_error = ""
        self.last_event_ts = 0.0
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    # ---- 生命周期
    def start(self) -> bool:
        self._thread = threading.Thread(target=self._loop, name="flowwatch-etw-batch", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.window + 8)
        self._run_logman("stop")          # 兜底：确保会话被关掉
        self._cleanup_files()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mode": "batch",
                "state": self.state,
                "detail": self.detail,
                "window_seconds": self.window,
                "rounds": self.rounds,
                "events": self.events,
                "learned": self.learned,
                "forgotten": self.forgotten,
                "sanity_failures": self.sanity_failures,
                "errors": self.errors,
                "last_error": self.last_error,
                "last_round_ms": round(self.last_round_ms, 1),
                "since_last_event": round(time.time() - self.last_event_ts, 1) if self.last_event_ts else None,
            }

    # ---- 主循环（独立线程，任何失败只记账）
    def _loop(self) -> None:
        while not self._stop_event.is_set():
            started = time.monotonic()
            try:
                self._one_round()
                if self.state == "idle":
                    self.state = "running"
            except Exception as exc:                     # 绝不让增强层影响主链路
                with self._lock:
                    self.errors += 1
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    if self.state != "denied":
                        self.state = "failed"
                        self.detail = self.last_error
            with self._lock:
                self.last_round_ms = (time.monotonic() - started) * 1000
            self._stop_event.wait(max(0.5, self.window - (time.monotonic() - started) * 0.5))

    def _one_round(self) -> None:
        etl = self.run_dir / f"{self.session}.etl"
        xml = self.run_dir / f"{self.session}.xml"
        self._cleanup_files(etl, xml)

        code, out = self._run_logman("start", ["-o", str(etl)])
        if code != 0:
            if code == 5 or "access is denied" in out.lower() or "拒绝访问" in out:
                with self._lock:
                    self.state, self.detail = "denied", "创建 ETW 会话需要管理员（logman -ets）"
                self._stop_event.set()
                return
            raise RuntimeError(f"logman start 失败 rc={code}: {out}")
        self._stop_event.wait(self.window)
        self._run_logman("stop")

        if not etl.exists():
            raise RuntimeError("logman 未生成 ETL")
        code, out = self._convert(etl, xml)
        if code != 0 or not xml.exists():
            raise RuntimeError(f"tracerpt 失败 rc={code}: {out}")
        events = parse_dump(xml.read_bytes())
        self._apply(events)
        self._cleanup_files(etl, xml)

    def _apply(self, events: list[dict[str, Any]]) -> None:
        local_ips = self.local_ips_provider() or set()
        with self._lock:
            self.rounds += 1
            self.events += len(events)
            if events:
                self.last_event_ts = time.time()
        for event in events:
            if local_ips and not etw.sane(event, local_ips):
                with self._lock:
                    self.sanity_failures += 1
                continue
            key = (event["saddr"], event["sport"], event["daddr"], event["dport"])
            if event["kind"] == "learn":
                self.conn_memory.remember(key, event["pid"])
                with self._lock:
                    self.learned += 1
            else:
                self.conn_memory.forget(key)
                with self._lock:
                    self.forgotten += 1

    # ---- 子进程
    def _run_logman(self, action: str, extra: list[str] | None = None) -> tuple[int, str]:
        args = ["logman", action, self.session]
        if action == "start":
            args += ["-p", self.provider, KEYWORDS, LEVEL, "-ets"] + list(extra or [])
        else:
            args += ["-ets"]
        return self._exec(args)

    @staticmethod
    def _convert(etl: Path, xml: Path) -> tuple[int, str]:
        return EtwBatchTracker._exec(["tracerpt", str(etl), "-o", str(xml), "-of", "XML", "-y"])

    @staticmethod
    def _exec(args: list[str]) -> tuple[int, str]:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        proc = subprocess.run(args, capture_output=True, text=True, errors="replace",
                              timeout=120, creationflags=flags)
        return proc.returncode, ((proc.stdout or "").strip() or (proc.stderr or "").strip())

    def _cleanup_files(self, *paths: Path) -> None:
        targets = list(paths) or sorted(self.run_dir.glob(f"{self.session}.*"))
        for path in targets:
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                pass
