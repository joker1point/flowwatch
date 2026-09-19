"""本机 TCP 连接归属 —— 补上抓包看不到的那一层。

为什么需要它（2026-09-19 事故复盘）：
抓包只能看到经过网卡的流量，而走本地代理的流量在网卡上只剩代理进程本身 ——
真实发起方（应用）与真实目标（被 TLS 隧道吞掉）都看不见，纯环回更是完全不经过网卡
（实测 `/api/rates` 里 `127.0.0.1` 出现 0 次）。出事时定位"谁在重试、谁在用代理"，
此前靠手工跑 `Get-NetTCPConnection -RemotePort 7890 | Group-Object OwningProcess`——
一次实测里某个后端进程 **292 条连接**、第二名只有 3 条，连接数本身就是最强的异常信号。

本模块把这一步自动化：按固定间隔快照系统 TCP 连接表（psutil，已在依赖里），
按进程聚合三个指标：
    · conns       活动连接总数
    · local_conns 指向「本机地址」的连接数（= 在用本机的代理/服务；环回也算）
    · new_per_sec 新出现的本机侧端点速率（短连接风暴会在这里爆表）
外带 services 榜：本机监听端口 ← 有哪些进程在连它（谁在监听、几个客户端）。

只读元数据：pid / 地址 / 端口 / 状态。不读内容、不发包、不做任何连接操作。
"""

import logging
import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import psutil

logger = logging.getLogger("flowwatch.localconn")

DEFAULT_INTERVAL = 1.5     # 与端点表同频：连接表快照成本低，节奏也够用
TOP_PEERS = 4              # 每个进程最多带几个"在连哪个本地端口"
TOP_SERVICES = 12          # 服务榜条数上限
TOP_ROWS = 40              # 进程行数上限（只保留有连接的）


@dataclass
class _Proc:
    conns: int = 0
    local_conns: int = 0
    peers: Counter = field(default_factory=Counter)   # 对端端口 → 连接数（仅本机目标）
    keys: set = field(default_factory=set)            # 本快照的本机侧端点（算新建速率）


class LocalConnTable:
    """周期性快照系统 TCP 连接表并聚合。刷新线程写、API 线程读，用锁隔开。"""

    def __init__(self, interval: float = DEFAULT_INTERVAL) -> None:
        self.refresh_interval = interval
        self.source = "init"
        self.error = ""
        self.last_cost_ms = 0.0
        self.updated_at = 0.0
        self.total_conns = 0
        self.local_conns = 0
        self._procs: dict[int, _Proc] = {}
        self._names: dict[int, str] = {}
        self._services: list[dict[str, Any]] = []
        self._new_per_sec: dict[int, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ---------------------------------------------------------------- 采集

    def refresh(self) -> None:
        """快照一次连接表并重新聚合。失败只记录，保留上次结果（不打断服务）。"""
        t0 = time.monotonic()
        try:
            conns = psutil.net_connections("tcp")
        except Exception as exc:               # 权限或表结构异常
            self.error = f"{type(exc).__name__}: {exc}"
            self.last_cost_ms = (time.monotonic() - t0) * 1000
            return
        self.source = "psutil"
        self.error = ""
        local_ips = self._local_addresses()

        procs: dict[int, _Proc] = {}
        listen_owner: dict[int, int] = {}      # 监听端口 → 属主 pid
        clients: dict[int, set[int]] = {}      # 监听端口 → 客户端 pid 集合
        client_conns: Counter = Counter()      # 监听端口 → 连接数
        total = local_total = 0

        for conn in conns:
            if conn.status == "LISTEN":
                if conn.pid is not None and conn.laddr:
                    listen_owner.setdefault(conn.laddr.port, conn.pid)
                continue
            if conn.status != "ESTABLISHED" or conn.pid is None or not conn.raddr:
                continue
            pid = conn.pid
            item = procs.get(pid)
            if item is None:
                item = procs[pid] = _Proc()
            item.conns += 1
            total += 1
            peer = conn.raddr
            if peer.ip in local_ips:           # 目标是自己：在用本机的代理/服务
                item.local_conns += 1
                item.peers[peer.port] += 1
                item.keys.add(((conn.laddr.port if conn.laddr else 0), peer.port))
                local_total += 1
                client_conns[peer.port] += 1
                clients.setdefault(peer.port, set()).add(pid)

        # 新建速率：与上次快照比本机侧端点新增了多少（短连接风暴在这里爆表）。
        # 首帧没有基线，宁可给 0 也不编一个假速率出来（除以 1ms 会得到荒唐的 4000）。
        now = time.monotonic()
        first = not self.updated_at
        elapsed = 0.0 if first else max(1e-3, now - self.updated_at)
        with self._lock:
            prev = {pid: item.keys for pid, item in self._procs.items()}
        new_per_sec = {
            pid: (len(item.keys - (prev.get(pid) or set())) / elapsed if elapsed else 0.0)
            for pid, item in procs.items()
        }

        names: dict[int, str] = {}
        for pid in procs:
            names[pid] = self._proc_name(pid, names)
        services = []
        for port, count in client_conns.most_common(TOP_SERVICES):
            owner = listen_owner.get(port)
            services.append({
                "port": port,
                "pid": owner,
                "process": self._proc_name(owner, names) if owner is not None else None,
                "clients": len(clients.get(port, ())),
                "conns": count,
            })

        with self._lock:
            self._procs = procs
            self._names = names
            self._services = services
            self._new_per_sec = new_per_sec
            self.total_conns = total
            self.local_conns = local_total
            self.updated_at = now
            self.last_cost_ms = (time.monotonic() - t0) * 1000

    @staticmethod
    def _local_addresses() -> set[str]:
        """本机所有接口地址（含回环）。实测很便宜，和连接表一起刷即可。"""
        addrs = {"127.0.0.1", "::1"}
        try:
            for items in psutil.net_if_addrs().values():
                for item in items:
                    if item.family in (socket.AF_INET, socket.AF_INET6):
                        addrs.add(item.address.split("%")[0])
        except Exception:
            pass
        return addrs

    @staticmethod
    def _proc_name(pid: int | None, cache: dict[int, str]) -> str:
        if pid is None:
            return ""
        if pid in cache:
            return cache[pid]
        try:
            name = psutil.Process(pid).name()
        except Exception:
            name = f"pid-{pid}"
        cache[pid] = name
        return name

    # ---------------------------------------------------------------- 读取

    def snapshot(self) -> dict[str, Any]:
        """给帧用的只读快照。**按 local_conns 再按 conns 排序** —— 出事时它排最前。"""
        with self._lock:
            rows = [
                {
                    "pid": pid,
                    "process": self._names.get(pid, f"pid-{pid}"),
                    "conns": item.conns,
                    "local_conns": item.local_conns,
                    "new_per_sec": round(self._new_per_sec.get(pid, 0.0), 1),
                    "top_peers": [
                        {"port": port, "conns": count}
                        for port, count in item.peers.most_common(TOP_PEERS)
                    ],
                }
                for pid, item in self._procs.items()
            ]
            rows.sort(key=lambda row: (row["local_conns"], row["conns"]), reverse=True)
            return {
                "source": self.source,
                "error": self.error,
                "refresh_ms": round(self.last_cost_ms, 1),
                "refresh_interval": self.refresh_interval,
                "total_conns": self.total_conns,
                "local_conns": self.local_conns,
                "by_pid": rows[:TOP_ROWS],
                "services": self._services,
            }

    # ---------------------------------------------------------------- 生命周期

    def loop(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self.refresh_interval)

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.loop, name="flowwatch-localconn", daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self._stop.set()
