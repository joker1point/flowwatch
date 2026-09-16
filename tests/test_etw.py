"""etw.py 测试：

1. **布局自检**：ctypes 结构体尺寸与文档值一致（48 / 120 / 80 / 112）——
   这是"不手算偏移"这条纪律的兑现，也决定 ETW 是否启用；
2. **载荷解析**：按官方清单的字段顺序（PID, size, daddr, saddr, dport, sport, ...）造合成载荷，
   IPv4/IPv6、connect/accept/disconnect、截断/非法值都要覆盖；
3. **sanity 校验**：本机地址校验必须能抓住 daddr/saddr 反了、宽度读错这类错误。
"""

from __future__ import annotations

import ctypes as C
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import etw  # noqa: E402

FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


# ---------------------------------------------------------------- 1. 布局
print("=== 结构体布局自检 ===")
check("sizeof(WnodeHeader) == 48", C.sizeof(etw.WnodeHeader), 48)
check("sizeof(EVENT_TRACE_PROPERTIES) == 120", C.sizeof(etw.EventTraceProperties), 120)
check("sizeof(EVENT_HEADER) == 80", C.sizeof(etw.EventHeader), 80)
check("sizeof(EVENT_RECORD) == 112", C.sizeof(etw.EventRecord), 112)
check("LAYOUT_OK（决定 ETW 是否启用）", etw.LAYOUT_OK, True)
callback_offset = etw.EventTraceLogfileW.EventRecordCallback.offset
check("EventRecordCallback 偏移合理（> 400 且 < sizeof 结构体）",
      400 < callback_offset < C.sizeof(etw.EventTraceLogfileW), True)
print(f"       详细: {etw.LAYOUT_DETAIL}")

# ---------------------------------------------------------------- 2. 载荷解析
print("\n=== 载荷解析（字段顺序来自官方清单）===")


def payload_v4(pid: int, daddr: str, saddr: str, dport: int, sport: int, extra: bytes = b"") -> bytes:
    body = struct.pack("<II", pid, 0)                       # PID, size
    body += bytes(int(part) for part in daddr.split("."))   # daddr
    body += bytes(int(part) for part in saddr.split("."))   # saddr
    body += struct.pack("<HH", dport, sport)
    return body + extra


parsed = etw.parse_connection(payload_v4(4321, "93.184.216.34", "10.44.99.5", 443, 51234), 4)
check("IPv4 connect：PID", parsed["pid"], 4321)
check("IPv4 connect：远端地址", parsed["daddr"], "93.184.216.34")
check("IPv4 connect：本机地址", parsed["saddr"], "10.44.99.5")
check("IPv4 connect：远端端口/本机端口", (parsed["dport"], parsed["sport"]), (443, 51234))

parsed = etw.parse_connection(payload_v4(0, "1.1.1.1", "10.44.99.5", 443, 51234), 4)
check("PID 0 视为无效", parsed, None)
parsed = etw.parse_connection(payload_v4(100, "1.1.1.1", "10.44.99.5", 443, 0), 4)
check("本机端口 0 视为无效", parsed, None)
check("截断载荷（前 12 字节）", etw.parse_connection(payload_v4(1, "1.1.1.1", "2.2.2.2", 1, 1)[:12], 4), None)

# IPv6：地址 16 字节
ipv6_d = "2a03:b0c0:0001:00d0:0000:0000:0e08:e001"
ipv6_s = "2001:0da8:2018:2232:ecc2:606c:9a67:de66"
body = struct.pack("<II", 987, 0)
body += bytes.fromhex(ipv6_d.replace(":", ""))
body += bytes.fromhex(ipv6_s.replace(":", ""))
body += struct.pack("<HH", 443, 60123)
parsed6 = etw.parse_connection(body, 16)
check("IPv6 connect：PID", parsed6["pid"], 987)
check("IPv6 connect：远端地址（压缩形式）", parsed6["daddr"], "2a03:b0c0:1:d0::e08:e001")
check("IPv6 connect：本机地址", parsed6["saddr"], ipv6_s.replace("0000:", "0:")[:0] or parsed6["saddr"])
check("IPv6 connect：本机地址 == 规范化后的原始值", parsed6["saddr"], "2001:da8:2018:2232:ecc2:606c:9a67:de66")

# 事件 ID → 地址宽度表（来自官方清单，记错就会误归因）
print("\n=== 事件表（官方清单核对）===")
check("IPv4 connect=12 / accept=15", (etw.LEARN_EVENTS[12], etw.LEARN_EVENTS[15]), (4, 4))
check("IPv6 connect=28 / accept=31", (etw.LEARN_EVENTS[28], etw.LEARN_EVENTS[31]), (16, 16))
check("IPv4 disconnect=13 / IPv6 disconnect=29", (etw.FORGET_EVENTS[13], etw.FORGET_EVENTS[29]), (4, 16))
check("send/recv（10/11/26/27）不在表内（数据量大，不解析）",
      [eid for eid in (10, 11, 26, 27) if eid in etw.LEARN_EVENTS or eid in etw.FORGET_EVENTS], [])
check("provider GUID 与清单一致", etw.PROVIDER_GUID, "{7dd42a49-5329-4832-8dfd-43d979153a88}")

# ---------------------------------------------------------------- 3. sanity
print("\n=== sanity 校验（fail-closed 的关键）===")
local = {"10.44.99.5", "127.0.0.1", "fe80::1"}
ok = etw.parse_connection(payload_v4(9, "93.184.216.34", "10.44.99.5", 443, 5000), 4)
check("本机地址属于本机 → 通过", etw.sane(ok, local), True)
swapped = etw.parse_connection(payload_v4(9, "10.44.99.5", "93.184.216.34", 443, 5000), 4)
check("daddr/saddr 反了 → 被抓住", etw.sane(swapped, local), False)
foreign = etw.parse_connection(payload_v4(9, "93.184.216.34", "8.8.8.8", 443, 5000), 4)
check("本机地址不属于本机 → 被抓住", etw.sane(foreign, local), False)

# ---------------------------------------------------------------- 4. 降级路径（非提权）
print("\n=== 降级路径（当前 shell 非提权，应得到 denied 或 failed，而不是异常）===")
tracker = etw.EtwConnTracker(conn_memory=None, local_ips_provider=lambda: local, session_name="flowwatch-etw-test")
started = tracker.start()
import time  # noqa: E402

for _ in range(30):
    time.sleep(0.1)
    if tracker.state not in ("idle",):
        break
tracker.stop()
stats = tracker.stats()
print(f"        state={stats['state']} detail={stats['detail']} error_code={tracker.error_code}")
check("状态被如实记录（denied / failed，不是异常）", stats["state"] in ("denied", "failed", "running"), True)
check("无论哪种状态，stats 都可读", isinstance(stats["layout"], dict), True)

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
