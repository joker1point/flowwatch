#!/usr/bin/env python3
"""flowwatch / 域名解析层

把 `IP:端口` 翻译成人看得懂的名字，**仍然只碰元数据**，两条证据来源：

  1. **DNS 应答**：抓到的 DNS 响应里本来就有 `名字 → IP`（A/AAAA 记录）。
     做的是"读我们已经抓到的元数据"，没有额外查询、没有反向解析、没有联网。
  2. **TLS ClientHello 的 SNI**：出站首包里的 server_name 扩展是**明文**的，
     而且它直接对应"这条连接要去哪"，比 DNS 更准（一个 IP 上挂着几百个站点）。

拿不到的（如实标注，不猜）：
  - **DoH / DoT**：DNS 走 443/853 且被加密 → 看不到 `名字→IP`；
  - **ECH（加密 ClientHello）**：SNI 被加密 → 看不到域名；
  - **QUIC**（HTTP/3，UDP 443）：Initial 里的 SNI 需要按 QUIC 密钥派生解密，本层不碰；
  - 上述情况一律显示 IP，不编造、不用第三方库猜。

隐私边界不变：只读 DNS 应答的记录字段与 TLS 握手的 SNI 字段，**不读证书、不读任何内容**。
"""

from __future__ import annotations

import threading
import time
from typing import Any

MAX_LABEL = 63
MAX_NAME_LEN = 255
MAX_POINTER_HOPS = 12        # DNS 压缩指针最多跳几次（防恶意/畸形包把解析拖死）
MAX_CACHE = 4096             # 每个缓存的上限，超了先清过期再清一半

# 常见 TLS 端口：只在这些端口上尝试解析 SNI（避免对每个包做无用判断）
TLS_PORTS = frozenset({443, 8443, 9443, 1443, 6443, 2053, 2083, 2087, 2096, 8843})
DNS_PORTS = frozenset({53, 5353})   # 5353 是 mDNS：应答里也有 名字→IP，同样有用


# ---------------------------------------------------------------- DNS
def _read_name(data: bytes, offset: int) -> tuple[str, int] | None:
    """读一个（可能带压缩指针的）DNS 名字。返回 (名字, 下一个位置)。"""
    labels: list[str] = []
    hops = 0
    position = offset
    end = -1            # 指针跳转前的"真实结束位置"
    total = 0
    while True:
        if position >= len(data):
            return None
        length = data[position]
        if length == 0:
            position += 1
            if end < 0:
                end = position
            break
        if length & 0xC0 == 0xC0:                 # 压缩指针
            if position + 1 >= len(data) or hops >= MAX_POINTER_HOPS:
                return None
            pointer = ((length & 0x3F) << 8) | data[position + 1]
            if end < 0:
                end = position + 2
            hops += 1
            position = pointer
            continue
        if length > MAX_LABEL:
            return None
        start = position + 1
        chunk = data[start:start + length]
        if len(chunk) != length:
            return None
        labels.append(chunk.decode("ascii", errors="replace"))
        total += length + 1
        if total > MAX_NAME_LEN:
            return None
        position = start + length
    if not labels or end < 0:
        return None
    return ".".join(labels).lower(), end


def dns_answers(payload: bytes) -> list[tuple[str, str]]:
    """从 DNS **响应**里抽出 (名字, IP) 列表（只认 A/AAAA，够用且稳）。

    只处理响应（QR=1）：查询包里没有答案，解析它没有意义。
    """
    if len(payload) < 12:
        return []
    flags = int.from_bytes(payload[2:4], "big")
    if flags & 0x8000 == 0:            # 不是响应
        return []
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    if ancount == 0 or ancount > 64:   # 畸形/超量：不处理
        return []

    offset = 12
    for _ in range(qdcount):           # 跳过问题区
        parsed = _read_name(payload, offset)
        if parsed is None:
            return []
        _name, offset = parsed
        offset += 4                    # QTYPE + QCLASS
    answers: list[tuple[str, str]] = []
    for _ in range(ancount):
        parsed = _read_name(payload, offset)
        if parsed is None:
            return answers
        name, offset = parsed
        if offset + 10 > len(payload):
            return answers
        rtype = int.from_bytes(payload[offset:offset + 2], "big")
        rdlength = int.from_bytes(payload[offset + 8:offset + 10], "big")
        offset += 10
        if offset + rdlength > len(payload):
            return answers
        if rtype == 1 and rdlength == 4:
            answers.append((name, ".".join(str(byte) for byte in payload[offset:offset + 4])))
        elif rtype == 28 and rdlength == 16:
            answers.append((name, _format_ipv6(payload[offset:offset + 16])))
        offset += rdlength
    return answers


def _format_ipv6(raw: bytes) -> str:
    import socket

    return socket.inet_ntop(socket.AF_INET6, raw).lower()


# ---------------------------------------------------------------- TLS SNI
def tls_sni(payload: bytes) -> str | None:
    """从 TLS ClientHello 里取 SNI（server_name 扩展）。取不到返回 None。"""
    if len(payload) < 6 or payload[0] != 0x16:       # 期望 handshake 记录
        return None
    if payload[5] != 0x01:                            # 期望 ClientHello
        return None
    try:
        position = 9                                  # 记录头(5) + 握手类型(1) + 长度(3)
        position += 2 + 32                            # legacy_version + random
        session_len = payload[position]
        position += 1 + session_len
        cipher_len = int.from_bytes(payload[position:position + 2], "big")
        position += 2 + cipher_len
        compression_len = payload[position]
        position += 1 + compression_len
        if position + 2 > len(payload):
            return None
        extensions_len = int.from_bytes(payload[position:position + 2], "big")
        position += 2
        limit = min(len(payload), position + extensions_len)
        while position + 4 <= limit:
            ext_type = int.from_bytes(payload[position:position + 2], "big")
            ext_len = int.from_bytes(payload[position + 2:position + 4], "big")
            position += 4
            if ext_type == 0x0000:                    # server_name
                if position + 5 > limit:
                    return None
                # 结构：list_len(2) + name_type(1) + name_len(2) + name
                name_len = int.from_bytes(payload[position + 3:position + 5], "big")
                start = position + 5
                host = payload[start:start + name_len].decode("ascii", errors="replace")
                host = host.strip().strip(".").lower()
                return host or None
            position += ext_len
    except (IndexError, ValueError):
        return None
    return None


def looks_like_client_hello(payload: bytes) -> bool:
    """廉价预筛：只对"像 ClientHello 的首包"做真解析（热路径上先过这一关）。"""
    return (
        len(payload) >= 6
        and payload[0] == 0x16            # handshake
        and payload[1] == 0x03            # TLS 1.x
        and payload[2] in (0x00, 0x01, 0x02, 0x03)
        and payload[5] == 0x01            # ClientHello
    )


# ---------------------------------------------------------------- 解析器（带缓存）
class NameResolver:
    """`IP → 域名`（DNS 观测）与 `IP:端口 → 域名`（SNI 观测）两张有界缓存。

    两个键分开存，因为语义不同：
      - DNS 给的是"这个 IP 可能是谁"，一个 IP 上可能挂着很多站点（CDN）；
      - SNI 给的是"这条连接要去哪"，最准，优先用。
    """

    def __init__(self, dns_ttl: float = 600.0, sni_ttl: float = 1800.0) -> None:
        self.dns_ttl = dns_ttl
        self.sni_ttl = sni_ttl
        # 采集线程写（note_*）、API/历史线程读（describe）、刷新线程 prune —— 加锁串行化
        self._lock = threading.Lock()
        self._by_ip: dict[str, tuple[str, float]] = {}
        self._by_endpoint: dict[tuple[str, int], tuple[str, float]] = {}
        self.dns_records = 0        # 观测到的 DNS 答案条数
        self.sni_records = 0        # 观测到的 SNI
        self.lookups = 0
        self.hits = 0
        self.parse_errors = 0

    # ---- 写入（抓包线程调用，只做字典写，便宜）
    def note_dns(self, name: str, ip: str) -> None:
        if not name or not ip:
            return
        with self._lock:
            self._by_ip[ip] = (name, time.monotonic())
            self.dns_records += 1
            if len(self._by_ip) > MAX_CACHE:
                self._prune(self._by_ip, self.dns_ttl)

    def note_sni(self, ip: str, port: int, name: str) -> None:
        if not name or not ip:
            return
        with self._lock:
            self._by_endpoint[(ip, port)] = (name, time.monotonic())
            self.sni_records += 1
            if len(self._by_endpoint) > MAX_CACHE:
                self._prune(self._by_endpoint, self.sni_ttl)

    @staticmethod
    def _prune(cache: dict, ttl: float) -> None:
        """调用方必须已持有 self._lock（遍历期间别人插入会抛 size changed）。"""
        now = time.monotonic()
        for key in [key for key, (_value, stamp) in list(cache.items()) if now - stamp > ttl]:
            cache.pop(key, None)
        if len(cache) > MAX_CACHE:              # 还是太多：按时间清掉一半
            ordered = sorted(list(cache.items()), key=lambda item: item[1][1])
            for key, _value in ordered[: len(ordered) // 2]:
                cache.pop(key, None)

    # ---- 读取
    def describe(self, remote: str) -> dict[str, str] | None:
        """`"1.2.3.4:443"` → `{"name": "example.com", "source": "sni|dns"}`；不知道返回 None。"""
        ip, _, port_text = remote.rpartition(":")
        port = int(port_text) if port_text.isdigit() else 0
        now = time.monotonic()
        with self._lock:
            self.lookups += 1
            entry = self._by_endpoint.get((ip, port))
            if entry and now - entry[1] <= self.sni_ttl:
                self.hits += 1
                return {"name": entry[0], "source": "sni"}
            entry = self._by_ip.get(ip)
            if entry and now - entry[1] <= self.dns_ttl:
                self.hits += 1
                return {"name": entry[0], "source": "dns"}
            return None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return self._stats_locked()

    def _stats_locked(self) -> dict[str, Any]:
        return {
            "dns_records": self.dns_records,
            "sni_records": self.sni_records,
            "ips_known": len(self._by_ip),
            "endpoints_known": len(self._by_endpoint),
            "lookups": self.lookups,
            "hits": self.hits,
            "hit_ratio": (self.hits / self.lookups) if self.lookups else 0.0,
            "parse_errors": self.parse_errors,
            "coverage_note": "DoH/DoT/ECH/QUIC 拿不到域名，如实显示 IP",
        }
