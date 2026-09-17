#!/usr/bin/env python3
"""flowwatch / 采集层

回答的问题：**这台机器上，哪个进程在跟谁通信、用了多少带宽。**

与 portwatch 的关系：portwatch 采集"谁占着哪个端口"（psutil 连接表 + 归因链路）；
本层采集"每个进程收发了多少字节"，数据源是抓包（元数据）+ 连接表（归因）。

设计要点（都来自实测）：
  1. Windows 上没有可用的"每连接字节数"API（`GetPerTcpConnectionEStats` 读回
     NOT_SUPPORTED，回环与非回环都一样），因此字节数只能靠抓包统计。
  2. 抓包走系统已装的 Npcap（`wpcap.dll`），用 ctypes 直接调用，**不需要额外
     Python 包、也不需要管理员**（除非 Npcap 安装时勾了"仅管理员可抓包"）。
  3. **端点表是快照，会漂移**：实测只取一次快照时未归因率高达 82%（新连接全落空）。
     所以端点表必须由独立线程周期性重建（默认 1.5s）。
  4. 抓包是 C 阻塞循环 → 放在独立线程里，只把"聚合后的计数"交给主流程，
     绝不逐包往事件循环里塞。
  5. 只统计元数据（IP / 端口 / 字节数），**不保存包体**——隐私边界写在设计里。
  6. **只统计本机流量**：混杂模式抓到的邻居广播/多播不属于这台机器，单列 foreign 计数、
     不混进未归因率（实测未归因中位数因此从 35% 降到 5% 量级）。

用法:
    python collector.py                     # 自动选最忙的网卡，前台打印 Top-N 速率
    python collector.py --dev WLAN          # 按设备名片段挑网卡
    python collector.py --seconds 20 --top 10
    python collector.py --list-devices      # 只列出 Npcap 设备
"""

from __future__ import annotations

import argparse
import ctypes as C
import etw
import etw_batch
import names
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import psutil

SCHEMA = "flowwatch/v1"

# ---------------------------------------------------------------- 常量
SNAPLEN = 2048           # 只看包头（隐私 + 性能）：IPv4/IPv6 + TCP/UDP 头都在前 128 字节内
PCAP_POLL_MS = 100       # pcap_next_ex 超时（毫秒），决定线程响应停止信号的速度
DEFAULT_FLUSH = 1.0      # 速率窗口（秒）
DEFAULT_ENDPOINT_REFRESH = 1.5   # 端点表重建周期（秒）

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# Windows 的地址族取值（注意 AF_INET6 在 Windows 上是 23，不是 Linux 的 10）
AF_INET = 2
AF_INET6 = 23
MASKED_PID = -1          # 端点已知、但属主受权限限制（非提权调用常见）
DWORD = C.c_uint32
BOOL = C.c_int


# ---------------------------------------------------------------- Npcap 封装
class PcapDevice(C.Structure):
    pass


PcapDevice._fields_ = [
    ("next", C.POINTER(PcapDevice)),
    ("name", C.c_char_p),
    ("description", C.c_char_p),
    ("addresses", C.c_void_p),
    ("flags", C.c_uint),
]


class PcapError(RuntimeError):
    pass


class Pcap:
    """对 wpcap.dll 的最小封装：列设备 / 打开 / 逐包读取 / 关闭。"""

    def __init__(self) -> None:
        try:
            self._lib = C.WinDLL("wpcap.dll")
        except OSError as exc:  # pragma: no cover - 取决于机器是否装了 Npcap
            raise PcapError("无法加载 wpcap.dll —— 需要安装 Npcap（https://npcap.com）") from exc
        self._lib.pcap_findalldevs.argtypes = [C.POINTER(C.POINTER(PcapDevice)), C.c_char_p]
        self._lib.pcap_findalldevs.restype = C.c_int
        self._lib.pcap_open_live.argtypes = [C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p]
        self._lib.pcap_open_live.restype = C.c_void_p
        self._lib.pcap_next_ex.argtypes = [C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_void_p)]
        self._lib.pcap_next_ex.restype = C.c_int
        self._lib.pcap_close.argtypes = [C.c_void_p]
        self._lib.pcap_freealldevs.argtypes = [C.POINTER(PcapDevice)]
        self._lib.pcap_geterr.argtypes = [C.c_void_p]
        self._lib.pcap_geterr.restype = C.c_char_p

    def devices(self) -> list[dict[str, str]]:
        errbuf = C.create_string_buffer(256)
        head = C.POINTER(PcapDevice)()
        if self._lib.pcap_findalldevs(C.byref(head), errbuf) != 0:
            raise PcapError("pcap_findalldevs 失败: " + errbuf.value.decode(errors="replace"))
        out: list[dict[str, str]] = []
        node = head
        while node:
            item = node.contents
            out.append(
                {
                    "name": (item.name or b"").decode(errors="replace"),
                    "description": (item.description or b"").decode(errors="replace") or "(无描述)",
                }
            )
            node = item.next
        self._lib.pcap_freealldevs(head)
        return out

    def open(self, device: str, promisc: int = 0) -> "PcapHandle":
        """打开设备。**默认非混杂模式**（promisc=0）：

        混杂模式会把广播域里别人的帧也送上来（实测邻居的 NetBIOS/SSDP 广播、多播），
        既污染"未归因率"这个指标，也越过隐私边界——这台机器只该统计它自己的流量。
        """
        errbuf = C.create_string_buffer(256)
        handle = self._lib.pcap_open_live(device.encode(), SNAPLEN, promisc, PCAP_POLL_MS, errbuf)
        if not handle:
            message = errbuf.value.decode(errors="replace")
            if "denied" in message.lower() or "permission" in message.lower():
                message += "（Npcap 可能勾选了『仅管理员可抓包』）"
            raise PcapError(f"打开设备失败: {message}")
        return PcapHandle(self._lib, handle)


class PcapHandle:
    def __init__(self, lib: Any, handle: int) -> None:
        self._lib = lib
        self._handle = handle
        self._hdr = C.c_void_p()
        self._data = C.c_void_p()

    def read(self) -> tuple[bytes, float] | None:
        """读一个包：返回 (帧字节, 时间戳秒)；超时返回 None；设备异常返回 None 并置 closed。"""
        rc = self._lib.pcap_next_ex(self._handle, C.byref(self._hdr), C.byref(self._data))
        if rc != 1 or not self._hdr:
            return None
        # struct pcap_pkthdr: timeval ts (tv_sec, tv_usec) + bpf_u_int32 caplen + len
        ts_sec = C.c_uint.from_address(self._hdr.value).value
        ts_usec = C.c_uint.from_address(self._hdr.value + 4).value
        caplen = C.c_uint.from_address(self._hdr.value + 8).value
        frame = C.string_at(self._data.value, int(caplen))
        return frame, ts_sec + ts_usec / 1e6

    def close(self) -> None:
        if self._handle:
            self._lib.pcap_close(self._handle)
            self._handle = None


# ---------------------------------------------------------------- 端点索引（四元组 → PID）
_IP_CACHE: dict[bytes, str] = {}


def _ip_text_v4(raw: bytes) -> str:
    """4 字节 → 点分十进制。带缓存：抓包热路径上同一个 IP 会反复出现。"""
    text = _IP_CACHE.get(raw)
    if text is None:
        text = socket.inet_ntoa(raw)
        _IP_CACHE[raw] = text
    return text


def _ip_text_v6(raw: bytes) -> str:
    """16 字节 → 压缩形式 IPv6（统一小写，保证与连接表两侧可直接比较）。"""
    text = _IP_CACHE.get(raw)
    if text is None:
        text = socket.inet_ntop(socket.AF_INET6, raw).lower()
        _IP_CACHE[raw] = text
    return text


class WinEndpointTable:
    """直接用 IP Helper API 取端点表：(ip, port) → pid。

    为什么不用 psutil：`psutil.net_connections(kind="inet")` 实测 **102–115 ms/次**
    （8731 条目）。直接调 API 要查 **4 张表**（v4/v6 × TCP/UDP），初次实现实测
    118–150 ms —— 比 psutil 还慢，因为**每行都调了 `ipaddress` 做规范化**
    （8000+ 次对象创建）。去掉规范化 + 加 IP 文本缓存后降到 **57–61 ms**
    （同条件 psutil 97–102 ms，即 1.7×；按 1.5s 刷新约占单核 4%）。

    教训：**"换成更底层的 API"不等于更快**，必须实测对照；而且对照的口径要对齐
    —— 最初的基准只测了 TCP v4 单表，真实实现要查 4 张表（v4/v6 × TCP/UDP），
    这种"苹果比橘子"的对照会把人带偏。
    """

    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1

    def __init__(self) -> None:
        self.available = False
        self.last_error: str | None = None
        try:
            self._lib = C.WinDLL("iphlpapi.dll")
        except OSError as exc:  # 非 Windows / 异常环境：调用方会退回 psutil
            self.last_error = str(exc)
            return
        for func in (self._lib.GetExtendedTcpTable, self._lib.GetExtendedUdpTable):
            func.argtypes = [C.c_void_p, C.POINTER(DWORD), BOOL, DWORD, DWORD, DWORD]
            func.restype = DWORD
        self.available = True

    def _rows(self, getter: Any, family: int, table_class: int, row_size: int) -> list[bytes]:
        size = DWORD(0)
        getter(None, C.byref(size), False, family, table_class, 0)   # 先问缓冲区多大
        if not size.value:
            return []
        buf = C.create_string_buffer(size.value)
        if getter(buf, C.byref(size), False, family, table_class, 0) != 0:
            return []
        count = C.cast(buf, C.POINTER(DWORD))[0]
        base = C.addressof(buf) + C.sizeof(DWORD)                    # 跳过 dwNumEntries
        return [C.string_at(base + i * row_size, row_size) for i in range(count)]

    def fetch(self) -> tuple[dict[tuple[str, int], int], dict[int, int]]:
        """返回 (exact, port_only)：与 psutil 版语义一致（全部状态 + TCP/UDP + v4/v6）。"""
        exact: dict[tuple[str, int], int] = {}
        port_only: dict[int, int] = {}

        def put(ip: str, port: int, pid: int) -> None:
            if pid == 0:
                # 非提权调用拿不到别人/SYSTEM 进程的 owning PID，会返回 0（实测 899/5394 条）。
                # 记成哨兵 -1：这样既不会把流量算到"System Idle Process"头上（错得离谱），
                # 又能单独成桶如实标注"属主受限"，提醒以管理员身份运行可获得完整归因。
                pid = MASKED_PID
            if ip in ("0.0.0.0", "::"):
                port_only.setdefault(port, pid)
            else:
                exact[(ip, port)] = pid

        # TCP v4：state, local(4B), localPort, remote(4B), remotePort, pid
        for row in self._rows(self._lib.GetExtendedTcpTable, AF_INET, self.TCP_TABLE_OWNER_PID_ALL, 24):
            local_addr, local_port, _ra, _rp, pid = struct.unpack_from("<IIIII", row, 4)
            put(_ip_text_v4(struct.pack("<I", local_addr)), socket.ntohs(local_port & 0xFFFF), pid)

        # TCP v6：local(16B), scope, localPort, remote(16B), scope, remotePort, state, pid
        for row in self._rows(self._lib.GetExtendedTcpTable, AF_INET6, self.TCP_TABLE_OWNER_PID_ALL, 56):
            local_addr = row[0:16]
            local_port, pid = struct.unpack_from("<II", row, 20)[0], struct.unpack_from("<I", row, 52)[0]
            put(_ip_text_v6(local_addr), socket.ntohs(local_port & 0xFFFF), pid)

        # UDP v4：local(4B), localPort, pid
        for row in self._rows(self._lib.GetExtendedUdpTable, AF_INET, self.UDP_TABLE_OWNER_PID, 12):
            local_addr, local_port, pid = struct.unpack_from("<III", row, 0)
            put(_ip_text_v4(struct.pack("<I", local_addr)), socket.ntohs(local_port & 0xFFFF), pid)

        # UDP v6：local(16B), scope, localPort, pid
        for row in self._rows(self._lib.GetExtendedUdpTable, AF_INET6, self.UDP_TABLE_OWNER_PID, 28):
            local_port, pid = struct.unpack_from("<II", row, 20)
            put(_ip_text_v6(row[0:16]), socket.ntohs(local_port & 0xFFFF), pid)

        return exact, port_only


class EndpointIndex:
    """连接表 → {(ip, port): pid}，供抓包线程把字节数算到进程头上。

    为什么需要它：抓到的包里只有 IP:port，没有 PID。连接表是唯一的"端点 → 进程"映射源。
    为什么要周期性重建：连接不断新建/关闭，只取一次快照会让新连接全部无法归因
    （实测未归因率 82%）。
    通配地址（0.0.0.0 / ::）的条目额外进 port_only 表：UDP 与监听态常用通配地址，
    没有它 UDP 几乎全部无法归因。

    取表优先走 IP Helper API（快 3×），失败时退回 psutil —— 归因是增强能力，
    任何一种取法不可用都不应该让采集停摆。
    """

    def __init__(self, refresh: float = DEFAULT_ENDPOINT_REFRESH) -> None:
        self.refresh_interval = refresh
        self.exact: dict[tuple[str, int], int] = {}
        self.port_only: dict[int, int] = {}
        self.updated_at: float = 0.0
        self.last_cost_ms: float = 0.0
        self.endpoints: int = 0
        self.source: str = "init"
        self._win = WinEndpointTable()
        # 端点表是快照，包是流水的：socket 常在两次刷新之间就关了。
        # 把刚消失的条目留一小会儿（TTL 6s ≫ 刷新周期 1.5s），能救回这部分流量。
        self.sticky_ttl: float = 6.0
        self.sticky_hits: int = 0
        self._sticky: dict[tuple[str, int], tuple[int, float]] = {}

    def refresh(self) -> None:
        t0 = time.monotonic()
        if self._win.available:
            try:
                exact, port_only = self._win.fetch()
            except Exception as exc:      # 表结构异常等：退回 psutil
                self._win.available = False
                self._win.last_error = str(exc)
                exact, port_only = self._via_psutil()
                self.source = "psutil(api-fallback)"
            else:
                self.source = "iphlpapi"
        else:
            exact, port_only = self._via_psutil()
            self.source = "psutil"
        if exact or port_only:
            self.exact = exact
            self.port_only = port_only
            self.endpoints = len(exact) + len(port_only)
            self.updated_at = time.time()
            now = time.monotonic()
            sticky = {key: (pid, now) for key, pid in exact.items()}
            for key, (pid, stamp) in self._sticky.items():
                if key not in sticky and now - stamp <= self.sticky_ttl:
                    sticky[key] = (pid, stamp)          # 刚从表里消失的：短 TTL 内仍然认
            self._sticky = sticky
        self.last_cost_ms = (time.monotonic() - t0) * 1000

    @staticmethod
    def _via_psutil() -> tuple[dict[tuple[str, int], int], dict[int, int]]:
        exact: dict[tuple[str, int], int] = {}
        port_only: dict[int, int] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return exact, port_only          # 权限不足：如实降级，保留上一次映射
        for conn in conns:
            if not conn.laddr or conn.pid is None:
                continue
            ip = conn.laddr.ip
            if ":" in ip:                     # IPv6 统一小写，与抓包侧一致
                ip = ip.lower()
            if ip in ("0.0.0.0", "::"):
                port_only.setdefault(conn.laddr.port, conn.pid)
            else:
                exact[(ip, conn.laddr.port)] = conn.pid
        return exact, port_only

    def pid_of(self, ip: str, port: int) -> int | None:
        pid = self.exact.get((ip, port))
        if pid is not None:
            return pid
        pid = self.port_only.get(port)
        if pid is not None:
            return pid
        item = self._sticky.get((ip, port))
        if item is not None:
            self.sticky_hits += 1
        return item[0] if item else None


class ConnMemory:
    """四元组 → PID 的短期记忆，用于端点表已经丢失的包。

    为什么按**四元组**记：端点表只回答"某个 (ip, port) 现在归谁"，而抓到的包
    自带完整四元组。一个四元组在 TIME_WAIT 期内不会被复用（Windows 默认 120s），
    所以"这个四元组刚才属于谁"是**观测事实**，不是"端口大概归谁"式的推测 ——
    比端口级推断更硬，也不会把并发的两个连接搞混。

    TTL 取 30s：远小于 TIME_WAIT，避免撞上端口复用；容量有界，超了先清过期、再清一半。
    """

    def __init__(self, ttl: float = 30.0, capacity: int = 4096) -> None:
        self.ttl = ttl
        self.capacity = capacity
        self.hits = 0
        # 采集线程写、刷新线程 prune —— **必须有锁**：不加锁时 prune 遍历到一半被插入，
        # 会抛 "dictionary changed size during iteration"（实测在线运行时报出过）。
        self._lock = threading.Lock()
        self._items: dict[tuple[str, int, str, int], tuple[int, float]] = {}

    def remember(self, key: tuple[str, int, str, int], pid: int) -> None:
        with self._lock:
            if len(self._items) >= self.capacity:
                self._prune_locked(force=True)
            self._items[key] = (pid, time.monotonic())

    def lookup(self, key: tuple[str, int, str, int]) -> int | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            self.hits += 1
            return item[0]

    def forget(self, key: tuple[str, int, str, int]) -> None:
        """立刻忘掉一个四元组（ETW 断开事件到达时用）—— 比等 TTL 过期干净。"""
        with self._lock:
            self._items.pop(key, None)

    def prune(self, force: bool = False) -> int:
        with self._lock:
            return self._prune_locked(force)

    def _prune_locked(self, force: bool = False) -> int:
        now = time.monotonic()
        stale = [key for key, (_, stamp) in list(self._items.items()) if now - stamp > self.ttl]
        for key in stale:
            del self._items[key]
        if force and len(self._items) >= self.capacity:
            ordered = sorted(list(self._items.items()), key=lambda item: item[1][1])
            for key, _ in ordered[: len(ordered) // 2]:
                del self._items[key]
        return len(stale)


# ---------------------------------------------------------------- 抓包线程
class FlowAggregator:
    """按进程聚合收发字节；每 flush 窗口吐一次速率。

    窗口计数刻意用"清零再累计"的方式（而不是两次累计值相减），
    这样即使读取方节奏不稳定，也只会拿到"上一窗口的速率"而不是被平均掉。
    """

    UNKNOWN_FLOW_LIMIT = 256  # 诊断用明细的有界容量；实测 48 条会被广播噪声撑爆
    ROLLING_WINDOWS = 60      # 滚动质量指标窗口数（默认 1s 一窗 ≈ 一分钟）
    DOMAIN_LIMIT = 64         # 每个窗口最多输出多少个域名条目（其余并入"(其他域名)"）

    def __init__(self, resolver: Any = None) -> None:
        self.resolver = resolver          # names.NameResolver：域名汇总要用（可为 None）
        self._lock = threading.Lock()
        self._rolling: deque[tuple[int, int, int]] = deque(maxlen=self.ROLLING_WINDOWS)
        self.last_quality: dict[str, Any] = {}
        self._win: dict[int, dict[str, Any]] = {}
        self._rates: dict[int, dict[str, Any]] = {}
        self._window_started = time.monotonic()
        self._unknown_bytes = 0
        self._unknown_packets = 0
        self._unknown_out = 0
        self._unknown_in = 0
        self._unknown_flows: dict[str, list[int]] = {}
        self._foreign_win_bytes = 0
        self._foreign_win_packets = 0
        self._skipped_win = 0
        self.last_unknown: dict[str, Any] = {}
        self.packets = 0
        self.bytes_total = 0
        self.parse_errors = 0
        self.foreign_packets = 0     # 两端都不是本机 IP（广播域里别人的帧）
        self.foreign_bytes = 0
        self.skipped_packets = 0     # 非 TCP/UDP 或头部不全：不参与任何统计

    def add(self, pid: int, remote: str | None, is_out: bool, length: int) -> None:
        with self._lock:
            self.packets += 1
            self.bytes_total += length
            slot = self._win.get(pid)
            if slot is None:
                slot = {"out": 0, "in": 0, "conns": defaultdict(lambda: [0, 0]), "packets": 0}
                self._win[pid] = slot
            if is_out:
                slot["out"] += length
            else:
                slot["in"] += length
            slot["packets"] += 1
            if remote:
                pair = slot["conns"][remote]
                pair[0 if is_out else 1] += length

    def add_unattributed(self, flow: str, is_out: bool, length: int) -> None:
        """有包但查不到 PID。**必须记明细**：只说"未归因 35%"没法改进，得知道是哪条流。"""
        with self._lock:
            self.packets += 1
            self.bytes_total += length
            self._unknown_bytes += length
            self._unknown_packets += 1
            if is_out:
                self._unknown_out += length
            else:
                self._unknown_in += length
            slot = self._unknown_flows.get(flow)
            if slot is None:
                if len(self._unknown_flows) >= self.UNKNOWN_FLOW_LIMIT:
                    slot = self._unknown_flows.setdefault("(长尾其他)", [0, 0, 0])
                else:
                    slot = self._unknown_flows[flow] = [0, 0, 0]
            slot[0 if is_out else 1] += length
            slot[2] += 1

    def add_foreign(self, length: int) -> None:
        """两端都不是本机地址：属于**别人的流量**，既不算归因成功也不算归因失败。

        单列出来是为了让"未归因率"这个指标干净——它应该只衡量"本机流量里有多少
        说不清是谁的"，不该被广播域里的邻居帧稀释或污染。
        """
        with self._lock:
            self.foreign_packets += 1
            self.foreign_bytes += length
            self._foreign_win_packets += 1
            self._foreign_win_bytes += length

    def mark_skipped(self) -> None:
        with self._lock:
            self.skipped_packets += 1
            self._skipped_win += 1

    def _domain_rollup(self, win: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
        """把窗口里每条连接的字节数归到**域名**上（未识别的按 IP 归，`kind="ip"`）。

        跑在 `self._win` 上（含全部连接），不是跑了截断的 rates —— 否则"哪个域名用了多少"
        会变成下界。条目数有界，保证落库写入量可预测。
        """
        resolver = self.resolver
        acc: dict[tuple[str, str], list[int]] = {}
        for slot in win.values():
            for remote, pair in slot["conns"].items():
                found = resolver.describe(remote) if resolver is not None else None
                if found:
                    key = (found["name"], found["source"])
                else:
                    key = (remote.rpartition(":")[0] or remote, "ip")
                item = acc.get(key)
                if item is None:
                    item = acc[key] = [0, 0, 0]
                item[0] += pair[0]
                item[1] += pair[1]
                item[2] += 1
        if not acc:
            return []
        ordered = sorted(acc.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)
        out = [
            {"name": name, "kind": kind, "out_bytes": value[0], "in_bytes": value[1],
             "conns": value[2]}
            for (name, kind), value in ordered[: self.DOMAIN_LIMIT]
        ]
        rest = [0, 0, 0]
        for (_name, _kind), value in ordered[self.DOMAIN_LIMIT:]:
            rest[0] += value[0]
            rest[1] += value[1]
            rest[2] += value[2]
        if rest[0] or rest[1]:
            out.append({"name": "(其他域名)", "kind": "other", "out_bytes": rest[0],
                        "in_bytes": rest[1], "conns": rest[2]})
        return out

    def flush(self) -> dict[str, Any]:
        """把窗口计数换算成速率并对外暴露（窗口时长由调用方给出）。"""
        with self._lock:
            now = time.monotonic()
            window = max(1e-3, now - self._window_started)
            domains = self._domain_rollup(self._win)
            rates: dict[int, dict[str, Any]] = {}
            for pid, slot in self._win.items():
                rates[pid] = {
                    "out_bps": slot["out"] / window,
                    "in_bps": slot["in"] / window,
                    "out_bytes": slot["out"],
                    "in_bytes": slot["in"],
                    "packets": slot["packets"],
                    "conns": sorted(
                        (
                            {"remote": remote, "out_bytes": pair[0], "in_bytes": pair[1]}
                            for remote, pair in slot["conns"].items()
                        ),
                        key=lambda item: item["out_bytes"] + item["in_bytes"],
                        reverse=True,
                    )[:12],
                }
            self._rates = rates
            self._window_started = now
            self._win = {}
            unknown_bytes, unknown_packets = self._unknown_bytes, self._unknown_packets
            flows = sorted(
                (
                    {"flow": flow, "out_bytes": item[0], "in_bytes": item[1], "packets": item[2]}
                    for flow, item in self._unknown_flows.items()
                ),
                key=lambda entry: entry["out_bytes"] + entry["in_bytes"],
                reverse=True,
            )[:8]
            unknown_out, unknown_in = self._unknown_out, self._unknown_in
            foreign_bytes_win, foreign_packets_win = self._foreign_win_bytes, self._foreign_win_packets
            skipped_win = self._skipped_win
            self._unknown_bytes = 0
            self._unknown_packets = 0
            self._unknown_out = 0
            self._unknown_in = 0
            self._unknown_flows = {}
            self._foreign_win_bytes = 0
            self._foreign_win_packets = 0
            self._skipped_win = 0
            attributed_bytes = sum(item["out_bytes"] + item["in_bytes"] for item in rates.values())
            self.last_unknown = {
                "bytes": unknown_bytes,
                "packets": unknown_packets,
                "attributed_bytes": attributed_bytes,
                "ratio": unknown_bytes / (attributed_bytes + unknown_bytes)
                if (attributed_bytes or unknown_bytes) else 0.0,
            }
            # 滚动质量指标：单窗口比率在空闲窗口会剧烈波动（分母太小），
            # 近 N 个窗口的合计比率才是能拿出去说的口径；windows 一起给出，便于判断样本量
            masked_bytes = sum(
                item["out_bytes"] + item["in_bytes"] for pid, item in rates.items() if pid < 0
            )
            self._rolling.append((attributed_bytes, unknown_bytes, masked_bytes))
            totals = [sum(column) for column in zip(*self._rolling)]
            rolling_attributed, rolling_unknown, rolling_masked = totals
            denominator = rolling_attributed + rolling_unknown
            quality = {
                "windows": len(self._rolling),
                "attributed_bytes": rolling_attributed,
                "unknown_bytes": rolling_unknown,
                "masked_bytes": rolling_masked,
                "unknown_ratio": (rolling_unknown / denominator) if denominator else 0.0,
                "masked_ratio": (rolling_masked / denominator) if denominator else 0.0,
            }
            self.last_quality = quality
            return {
                "window": window,
                "by_pid": rates,
                "domains": domains,              # 域名维度汇总（全量连接，非截断）
                "quality": quality,              # 60 秒滚动质量指标
                "unknown_bytes": unknown_bytes,
                "unknown_packets": unknown_packets,
                "unknown_out": unknown_out,          # 未归因的方向也不能丢：历史桶要分行落库
                "unknown_in": unknown_in,
                "unknown_flows": flows,
                "foreign_bytes_window": foreign_bytes_win,      # 本窗口增量（累计值在 stats）
                "foreign_packets_window": foreign_packets_win,
                "skipped_packets_window": skipped_win,
            }

    def rates(self) -> dict[int, dict[str, Any]]:
        with self._lock:
            return self._rates

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "packets": self.packets,
                "bytes": self.bytes_total,
                "parse_errors": self.parse_errors,
                "foreign_packets": self.foreign_packets,
                "foreign_bytes": self.foreign_bytes,
                "skipped_packets": self.skipped_packets,
                "masked_bytes": sum(
                    item["out_bytes"] + item["in_bytes"]
                    for pid, item in self._rates.items() if pid == MASKED_PID
                ),
            }


class Capturer:
    """抓包 + 归因 + 聚合：一个抓包线程 + 一个端点表刷新线程。"""

    def __init__(
        self,
        device: str | None = None,
        endpoint_refresh: float = DEFAULT_ENDPOINT_REFRESH,
        include_loopback: bool = True,
    ) -> None:
        self.pcap = Pcap()
        self.device = device
        self.include_loopback = include_loopback
        self.index = EndpointIndex(endpoint_refresh)
        self.resolver = names.NameResolver()  # IP:端口 → 域名（DNS 应答 / TLS SNI）
        self.aggregator = FlowAggregator(self.resolver)   # 域名汇总需要解析器
        self.local_ips: set[str] = set()     # 本机接口地址：判定"这段流量是不是这台机器的"
        self.conn_memory = ConnMemory()      # 四元组 → PID：端点表丢失时的兜底
        self.refresh_error: str | None = None   # 刷新级抖动（下次成功即清除），与致命 error 分开
        # ETW 归因（增强层）。两条路线都实现过、都实测过，结论如下（详见两个模块头部）：
        #   · etw.py       实时消费（OpenTraceW + ProcessTrace）：**2026-09-17 修好并实测通过** ——
        #                  根因是 EVENT_TRACE_HEADER 多 8 字节导致回调指针偏移错位（零回调），
        #                  靠与成熟库 pywintrace 逐项对照结构体布局定位。需要管理员；
        #                  非提权时如实降级为 denied（会话建不起来，主链路不受影响）。
        #   · etw_batch.py 批量路线（logman + tracerpt）：可用，但窗口 3 秒 → 学到 PID 时短命 socket
        #                  早已结束，**救不了那 30%**，只对"窗口内仍存活"的连接有补充意义。
        # 两者当前都**默认关闭**：实时路线需要管理员，且"该不该常开"应由实测收益决定
        # （见 README《归因质量》里的测量：开 ETW 前后未归因率与属主受限字节的对比）。
        self.etw = etw.EtwConnTracker(self.conn_memory, lambda: self.local_ips)
        self.etw_batch = etw_batch.EtwBatchTracker(
            self.conn_memory, lambda: self.local_ips, run_dir=Path(__file__).resolve().parent / "_run")
        self.use_etw = False
        self.use_etw_batch = False
        self.error: str | None = None
        self.device_name: str = ""
        self._handles: list[PcapHandle] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # ---- 本机地址
    def refresh_local_ips(self) -> None:
        """取本机所有接口地址（含回环、VPN、Tailscale）。实测 <2 ms，可与端点表同频刷新。

        为什么需要：promisc=1 时网卡会把广播域里的帧也送上来（邻居的 mDNS/SSDP/DHCP），
        那些流量两端都不是本机地址 —— 把它们算进"未归因"会让指标失真，
        更别提这本来就不该是这台机器该看的流量（隐私边界）。
        """
        ips: set[str] = set()
        try:
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if not addr.address:
                        continue
                    if addr.family == socket.AF_INET:
                        ips.add(addr.address)
                    elif addr.family == socket.AF_INET6:
                        ips.add(addr.address.split("%")[0].lower())
        except Exception:
            pass
        if ips:
            self.local_ips = ips

    # ---- 设备选择
    def pick_devices(self) -> list[str]:
        devs = self.pcap.devices()
        if self.device:
            picked = [d["name"] for d in devs if self.device.lower() in d["name"].lower()
                      or self.device.lower() in d["description"].lower()]
            if not picked:
                raise PcapError(f"没有匹配 '{self.device}' 的设备")
            return picked
        # 自动：挑最忙的非回环设备（1 秒试抓），需要时再带上回环
        scored: list[tuple[int, dict[str, str]]] = []
        for dev in devs:
            count = self._sniff_count(dev["name"], 1.0)
            scored.append((count, dev))
            if self._stop.is_set():
                break
        scored.sort(key=lambda item: item[0], reverse=True)
        if not scored or scored[0][0] <= 0:
            raise PcapError("所有设备都抓不到包（网卡选错或本机无流量）")
        picked = [scored[0][1]["name"]]
        if self.include_loopback:
            for count, dev in scored:
                if count > 0 and ("loopback" in dev["description"].lower()
                                  or "loopback" in dev["name"].lower()):
                    picked.append(dev["name"])
                    break
        return picked

    def _sniff_count(self, device: str, seconds: float) -> int:
        try:
            handle = self.pcap.open(device)
        except PcapError:
            return -1
        n, t0 = 0, time.monotonic()
        try:
            while time.monotonic() - t0 < seconds and not self._stop.is_set():
                if handle.read():
                    n += 1
        finally:
            handle.close()
        return n

    # ---- 生命周期
    def start(self) -> None:
        devices = self.pick_devices()
        self.index.refresh()
        self.refresh_local_ips()
        for device in devices:
            self._handles.append(self.pcap.open(device))
        self.device_name = ", ".join(devices)

        for handle in self._handles:
            thread = threading.Thread(target=self._capture_loop, args=(handle,),
                                      name="flowwatch-capture", daemon=True)
            thread.start()
            self._threads.append(thread)
        refresher = threading.Thread(target=self._refresh_loop, name="flowwatch-endpoints", daemon=True)
        refresher.start()
        self._threads.append(refresher)
        if self.use_etw:
            self.etw.start()          # 实验性（见头部结论）：失败只记录状态，不影响抓包
        if self.use_etw_batch:
            self.etw_batch.start()    # 批量路线（需要管理员；opt-in）

    def stop(self) -> None:
        self._stop.set()
        for tracker in (self.etw, self.etw_batch):
            try:
                tracker.stop()
            except Exception:
                pass
        for thread in self._threads:
            thread.join(timeout=2.0)
        for handle in self._handles:
            handle.close()
        self._handles.clear()

    def _refresh_loop(self) -> None:
        """自适应刷新：未归因高说明连接在快速生灭（实测短命 socket 是主要缺口），
        此时把端点表刷新周期压到 0.4s（65ms/次 ≈ 单核 16%）；稳定后退回 1.5s 省 CPU。
        """
        while not self._stop.is_set():
            ratio = self.aggregator.last_unknown.get("ratio", 1.0)
            self.index.refresh_interval = (
                0.4 if ratio > 0.25 else 0.8 if ratio > 0.08 else DEFAULT_ENDPOINT_REFRESH
            )
            if self._stop.wait(self.index.refresh_interval):
                return
            try:
                self.index.refresh()
                self.refresh_local_ips()     # IP 会变（VPN 重连 / DHCP 续约 / 网卡切换）
                self.conn_memory.prune()     # 顺手清过期记忆，抓包热路径上零额外开销
            except Exception as exc:  # 归因辅助能力，失败不影响抓包
                # 抖动型错误：如实记录但**不污染 status**，下一次刷新成功就清掉
                self.refresh_error = f"端点表刷新失败: {exc}"
            else:
                self.refresh_error = None

    def _capture_loop(self, handle: PcapHandle) -> None:
        while not self._stop.is_set():
            try:
                item = handle.read()
            except Exception as exc:  # 设备被拔掉等：如实记录，退出该线程
                self.error = f"抓包异常: {exc}"
                return
            if item is None:
                continue
            frame, _ts = item
            self._handle_frame(frame)

    # ---- 包解析（只读头部，不落包体）
    def _handle_frame(self, frame: bytes) -> None:
        agg = self.aggregator
        try:
            if len(frame) < 14:
                agg.mark_skipped()               # 残帧：不参与统计
                return
            eth_type = struct.unpack_from("!H", frame, 12)[0]
            offset = 14
            if eth_type == ETH_P_VLAN and len(frame) >= 18:
                eth_type = struct.unpack_from("!H", frame, 16)[0]
                offset = 18

            if eth_type == ETH_P_IP:
                if len(frame) < offset + 20:
                    agg.mark_skipped()
                    return
                ihl = (frame[offset] & 0x0F) * 4
                proto = frame[offset + 9]
                src_ip = _ip_text_v4(frame[offset + 12:offset + 16])
                dst_ip = _ip_text_v4(frame[offset + 16:offset + 20])
                l4 = offset + ihl
            elif eth_type == ETH_P_IPV6:
                if len(frame) < offset + 40:
                    agg.mark_skipped()
                    return
                proto = frame[offset + 6]          # next header（不处理扩展头）
                src_ip = _ip_text_v6(frame[offset + 8:offset + 24])
                dst_ip = _ip_text_v6(frame[offset + 24:offset + 40])
                l4 = offset + 40
            else:
                agg.mark_skipped()               # ARP / 802.1X 之类：不是 IP 流量
                return

            if proto not in (IPPROTO_TCP, IPPROTO_UDP):
                agg.mark_skipped()               # ICMP / IPv6 扩展头承载的流量
                return
            if len(frame) < l4 + 4:
                agg.mark_skipped()
                return
            sport, dport = struct.unpack_from("!HH", frame, l4)
            length = len(frame)

            src_local = src_ip in self.local_ips
            dst_local = dst_ip in self.local_ips
            if not (src_local or dst_local):
                # 两端都不是本机地址：广播域里别人的帧。既不是本机流量，也不算归因失败 ——
                # 直接摘出去，让"未归因率"只衡量"本机流量里有多少说不清是谁的"。
                agg.add_foreign(length)
                return

            # 域名线索与归因无关，先顺手喂给解析器（只读明文元数据，见 names.py 的边界说明）
            self._sniff_names(frame, l4, proto, src_ip, sport, dst_ip, dport, src_local)

            # 四元组统一按"本机侧在前"归一化：这样两个方向共用同一个键，
            # 任一方向归因成功，反方向就能继承。
            if src_local:
                key = (src_ip, sport, dst_ip, dport)
            else:
                key = (dst_ip, dport, src_ip, sport)

            pid = self.index.pid_of(src_ip, sport)
            if pid is not None:
                agg.add(pid, f"{dst_ip}:{dport}", True, length)
                self.conn_memory.remember(key, pid)
                return
            pid = self.index.pid_of(dst_ip, dport)
            if pid is not None:
                agg.add(pid, f"{src_ip}:{sport}", False, length)
                self.conn_memory.remember(key, pid)
                return
            pid = self.conn_memory.lookup(key)
            if pid is not None:
                agg.add(pid, f"{dst_ip}:{dport}" if src_local else f"{src_ip}:{sport}",
                        src_local, length)
                return
            agg.add_unattributed(
                f"{src_ip}:{sport} → {dst_ip}:{dport}",
                is_out=src_local or not dst_local,
                length=length,
            )
        except (struct.error, ValueError):
            agg.parse_errors += 1


    # ---- 域名线索（只读明文元数据）
    def _sniff_names(self, frame: bytes, l4: int, proto: int, src_ip: str, sport: int,
                     dst_ip: str, dport: int, outbound: bool) -> None:
        """从**已经抓到的包**里读域名线索：

        - DNS 应答（UDP/TCP 53、mDNS 5353）→ `名字 → IP`；
        - 出站 TLS ClientHello 的 SNI → `IP:端口 → 域名`（比 DNS 准，绕开 CDN 同 IP 多站）。

        只读这两个明文字段，不读证书、不读内容；解析失败只记账（parse_errors），
        绝不影响归因与统计 —— 域名是锦上添花，不是主链路。
        """
        resolver = self.resolver
        try:
            if proto == IPPROTO_UDP:
                if sport not in names.DNS_PORTS and dport not in names.DNS_PORTS:
                    return
                payload = frame[l4 + 8:]
                if payload:
                    for host, ip in names.dns_answers(payload):
                        resolver.note_dns(host, ip)
                return

            header_len = (frame[l4 + 12] >> 4) * 4      # TCP 头长度
            if header_len < 20 or len(frame) < l4 + header_len:
                return
            payload = frame[l4 + header_len:]
            if not payload:
                return
            if sport in names.DNS_PORTS or dport in names.DNS_PORTS:
                for host, ip in names.dns_answers(payload):   # TCP 上的 DNS（大响应会走 TCP）
                    resolver.note_dns(host, ip)
                return
            if outbound and dport in names.TLS_PORTS and names.looks_like_client_hello(payload):
                host = names.tls_sni(payload[:1500])
                if host:
                    resolver.note_sni(dst_ip, dport, host)
        except Exception:
            resolver.parse_errors += 1


# ---------------------------------------------------------------- CLI
def _fmt_bytes(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:8.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _fmt_rate(value: float) -> str:
    return f"{_fmt_bytes(value).strip()}/s"


def render(agg: FlowAggregator, index: EndpointIndex, top: int, device: str,
           memory: ConnMemory | None = None, resolver: names.NameResolver | None = None) -> str:
    rates = agg.rates()
    rows = sorted(rates.items(), key=lambda kv: kv[1]["out_bps"] + kv[1]["in_bps"], reverse=True)[:top]
    last = agg.last_unknown
    quality = agg.last_quality
    saved = f" · 记忆救回 {memory.hits}" if memory else ""
    window_note = f"（本窗口 {last.get('ratio', 0.0) * 100:.1f}%）" if quality else ""
    lines = [
        f"device={device}  端点表 {index.endpoints} 个（{index.source}，刷新 {index.last_cost_ms:.0f} ms）"
        f"  未归因 近{quality.get('windows', 0)}s {quality.get('unknown_ratio', 0.0) * 100:.1f}%{window_note}"
        f" · 短时记忆命中 {index.sticky_hits}{saved}",
        f"{'PID':>7}  {'进程':<24} {'发送速率':>14} {'接收速率':>14} {'包数':>6}  主要对端",
    ]
    for pid, item in rows:
        try:
            name = psutil.Process(pid).name()
        except Exception:
            name = "?"
        top_remote = item["conns"][0]["remote"] if item["conns"] else "-"
        if resolver and top_remote != "-":
            found = resolver.describe(top_remote)
            if found:
                top_remote = f"{found['name']} [{top_remote}]"
        lines.append(
            f"{pid:>7}  {name[:24]:<24} {_fmt_rate(item['out_bps']):>14} "
            f"{_fmt_rate(item['in_bps']):>14} {item['packets']:>6}  {top_remote}"
        )
    return "\n".join(lines)


def render_diag(window: dict[str, Any], agg: FlowAggregator) -> str:
    """未归因明细：只报一个比例无法改进，必须看出是哪条流、属于哪一类。"""
    stats = agg.stats()
    attributed = sum(item["out_bytes"] + item["in_bytes"] for item in window["by_pid"].values())
    lines = [
        f"  本窗口已归因 {_fmt_bytes(attributed).strip()} / 未归因 {_fmt_bytes(window['unknown_bytes']).strip()}"
        f"（{window['unknown_packets']} 包）"
        f" · 累计分类：别人的流量 {stats['foreign_packets']} 包 / 非 TCP-UDP {stats['skipped_packets']} 包"
    ]
    for flow in window["unknown_flows"][:6]:
        total = flow["out_bytes"] + flow["in_bytes"]
        lines.append(
            f"    {total / 1024:9.1f} KiB {flow['packets']:>5} 包 "
            f"out {flow['out_bytes'] / 1024:8.1f}K in {flow['in_bytes'] / 1024:8.1f}K  {flow['flow']}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="flowwatch 采集层（抓包统计 + 按进程归因）")
    parser.add_argument("--dev", help="设备名/描述片段（默认自动挑最忙的）")
    parser.add_argument("--list-devices", action="store_true", help="只列出 Npcap 设备")
    parser.add_argument("--seconds", type=float, default=10.0, help="前台运行时长")
    parser.add_argument("--top", type=int, default=8, help="显示前 N 个进程")
    parser.add_argument("--no-loopback", action="store_true", help="不额外抓回环设备")
    parser.add_argument("--diag", action="store_true", help="每个窗口打印未归因明细与分类计数")
    parser.add_argument("--etw", action="store_true",
                        help="实时消费 ETW 补全归因（需管理员；修复见 etw.py 头部 2026-09-17 结案说明）")
    parser.add_argument("--etw-batch", action="store_true",
                        help="批量路线：logman + tracerpt 补全连接归属（需管理员，窗口 3 秒，救不了短命 socket）")
    args = parser.parse_args(argv)

    pcap = Pcap()
    if args.list_devices:
        for dev in pcap.devices():
            print(f"{dev['name']}\n    {dev['description']}")
        return 0

    capturer = Capturer(device=args.dev, include_loopback=not args.no_loopback)
    capturer.use_etw = args.etw
    capturer.use_etw_batch = args.etw_batch
    try:
        capturer.start()
    except PcapError as exc:
        print(f"启动失败: {exc}", file=sys.stderr)
        return 1

    print(f"抓包中（{args.seconds:g} 秒，Ctrl+C 可提前结束）…设备: {capturer.device_name}\n")
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            time.sleep(DEFAULT_FLUSH)
            window = capturer.aggregator.flush()
            print(render(capturer.aggregator, capturer.index, args.top, capturer.device_name,
                         capturer.conn_memory, capturer.resolver))
            if args.diag:
                print(render_diag(window, capturer.aggregator))
            print("-" * 100)
    except KeyboardInterrupt:
        pass
    finally:
        capturer.stop()

    stats = capturer.aggregator.stats()
    capturer.aggregator.flush()
    unknown = capturer.aggregator.last_unknown
    # 口径与 API 层一致：未归因 /（已归因 + 未归因），且分母是**本窗口**的字节
    print(f"\n汇总: 包 {stats['packets']} / 本机字节 {_fmt_bytes(stats['bytes']).strip()} / "
          f"解析错误 {stats['parse_errors']} / "
          f"未归因 {unknown.get('ratio', 0.0) * 100:.1f}%（{_fmt_bytes(unknown.get('bytes', 0)).strip()}）")
    print(f"分类: 别人的流量 {stats['foreign_packets']} 包 / {_fmt_bytes(stats['foreign_bytes']).strip()}"
          f" · 非 TCP-UDP 或头部不全 {stats['skipped_packets']} 包")
    print(f"归因兜底: 端点短时记忆命中 {capturer.index.sticky_hits} 次 / "
          f"四元组记忆命中 {capturer.conn_memory.hits} 次")
    realtime = capturer.etw.stats()
    batch = capturer.etw_batch.stats()
    print(f"ETW 实时路线（默认关闭，--etw 开启）: {realtime['state']}"
          + (f" —— {realtime['detail']}" if realtime["detail"] else ""))
    print(f"ETW 批量路线（默认关闭，--etw-batch 开启）: {batch['state']} · {batch['rounds']} 轮"
          f" / 学到 {batch['learned']} · 忘掉 {batch['forgotten']} · 均值 {batch['last_round_ms']:.0f} ms/轮"
          + (f" —— {batch['detail']}" if batch["detail"] else ""))
    domain = capturer.resolver.stats()
    print(f"域名解析: DNS 记录 {domain['dns_records']} 条 / SNI {domain['sni_records']} 条 · "
          f"已知 IP {domain['ips_known']} 个 / 端点 {domain['endpoints_known']} 个 · "
          f"命中率 {domain['hit_ratio'] * 100:.1f}%（{domain['hits']}/{domain['lookups']}）")
    if capturer.error:
        print("错误:", capturer.error)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
