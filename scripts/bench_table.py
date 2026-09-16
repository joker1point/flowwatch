"""连接表读取基准：现在的 struct.unpack 逐行 vs 基于 array 的批量解析。

目的：判断"把端点表刷新提到 10 Hz"是否划算 —— 60ms/次 时占单核 60%，不可能；
若能降到 ~15ms，10 Hz 就是单核 15%，可以考虑（短命 socket 才抓得到）。
"""

from __future__ import annotations

import ctypes as C
import socket
import struct
import sys
import time
from array import array
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import collector  # noqa: E402

DWORD = C.c_uint32
BOOL = C.c_int
AF_INET = 2
AF_INET6 = 23


def bench(label: str, fn, rounds: int = 5) -> tuple[float, int]:
    times: list[float] = []
    size = 0
    for _ in range(rounds):
        started = time.perf_counter()
        result = fn()
        times.append((time.perf_counter() - started) * 1000)
        size = len(result[0]) + len(result[1])
    best = min(times)
    print(f"{label:<28} 最快 {best:6.1f} ms  平均 {sum(times) / len(times):6.1f} ms  端点 {size}")
    return best, size


def current() -> tuple[dict, dict]:
    table = collector.WinEndpointTable()
    return table.fetch()


def array_based() -> tuple[dict, dict]:
    """同样查 4 张表，但用 array 批量取 dword，再按步长切片（替代逐行 struct.unpack）。"""
    lib = C.WinDLL("iphlpapi.dll")
    for func in (lib.GetExtendedTcpTable, lib.GetExtendedUdpTable):
        func.argtypes = [C.c_void_p, C.POINTER(DWORD), BOOL, DWORD, DWORD, DWORD]
        func.restype = DWORD

    def rows(getter, family: int, table_class: int, row_size: int) -> bytes:
        size = DWORD(0)
        getter(None, C.byref(size), False, family, table_class, 0)
        if not size.value:
            return b""
        buf = C.create_string_buffer(size.value)
        if getter(buf, C.byref(size), False, family, table_class, 0) != 0:
            return b""
        count = C.cast(buf, C.POINTER(DWORD))[0]
        return C.string_at(C.addressof(buf) + C.sizeof(DWORD), count * row_size)

    exact: dict[tuple[str, int], int] = {}
    port_only: dict[int, int] = {}
    cache: dict[int, str] = {}

    def ip_text(raw: int) -> str:
        text = cache.get(raw)
        if text is None:
            text = socket.inet_ntoa(struct.pack("<I", raw))
            cache[raw] = text
        return text

    # TCP v4：每行 6 个 dword（state, local_addr, local_port, remote_addr, remote_port, pid）
    data = rows(lib.GetExtendedTcpTable, AF_INET, 5, 24)
    words = array("I", data)
    for index in range(0, len(words), 6):
        local_addr = words[index + 1]
        local_port = socket.ntohs(words[index + 2] & 0xFFFF)
        pid = words[index + 5]
        if local_addr == 0:
            port_only.setdefault(local_port, pid)
        else:
            exact[(ip_text(local_addr), local_port)] = pid

    # UDP v4：每行 3 个 dword（local_addr, local_port, pid）
    data = rows(lib.GetExtendedUdpTable, AF_INET, 1, 12)
    words = array("I", data)
    for index in range(0, len(words), 3):
        local_addr = words[index]
        local_port = socket.ntohs(words[index + 1] & 0xFFFF)
        pid = words[index + 2]
        if local_addr == 0:
            port_only.setdefault(local_port, pid)
        else:
            exact[(ip_text(local_addr), local_port)] = pid
    return exact, port_only


print("=== 基准（越少越好）===")
base_ms, base_rows = bench("现状 struct.unpack", current)
fast_ms, fast_rows = bench("array 批量解析", array_based)
print(f"\n提速 {base_ms / fast_ms:.1f}×，端点数量级一致: {base_rows} vs {fast_rows}")
for hz in (5, 10, 20):
    print(f"若按 {hz:>2} Hz 轮询：现状占单核 {base_ms * hz / 10:.1f}% · 优化后 {fast_ms * hz / 10:.1f}%")
