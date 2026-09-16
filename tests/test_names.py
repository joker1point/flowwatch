"""names.py 单元测试：用**合成的** DNS / TLS 包验证解析，含压缩指针与畸形输入。

不需要 Npcap、不需要网络 —— 解析层是纯函数，先把它们钉死。
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import names  # noqa: E402

FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


# ---------------------------------------------------------------- 构造器
def encode_name(host: str) -> bytes:
    out = b""
    for label in host.split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_dns_response(qname: str, ip: str, *, pointer: bool = True, rtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", rtype, 1)
    owner = b"\xc0\x0c" if pointer else encode_name(qname)
    if rtype == 1:
        rdata = socket.inet_aton(ip)
    else:
        rdata = socket.inet_pton(socket.AF_INET6, ip)
    answer = owner + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + answer


def build_client_hello(host: str | None, *, truncated: bool = False, extra: bytes = b"") -> bytes:
    sni = b""
    if host is not None:
        raw = host.encode()
        entry = b"\x00" + struct.pack("!H", len(raw)) + raw
        sni = struct.pack("!HH", 0x0000, len(entry) + 2) + struct.pack("!H", len(entry)) + entry
    supported_versions = struct.pack("!HH", 0x002b, 3) + b"\x02\x03\x04"
    extensions = supported_versions + sni
    body = (
        b"\x03\x03" + bytes(32)
        + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake + extra
    return record[:36] if truncated else record


# ---------------------------------------------------------------- DNS
check(
    "DNS 响应（答案名用压缩指针）",
    names.dns_answers(build_dns_response("www.example.com", "93.184.216.34")),
    [("www.example.com", "93.184.216.34")],
)
check(
    "DNS 响应（答案名不压缩）",
    names.dns_answers(build_dns_response("api.test.io", "10.1.2.3", pointer=False)),
    [("api.test.io", "10.1.2.3")],
)
check(
    "DNS 响应（AAAA 记录）",
    names.dns_answers(build_dns_response("v6.example.com", "2001:db8::1", rtype=28)),
    [("v6.example.com", "2001:db8::1")],
)
query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + encode_name("x.com") + struct.pack("!HH", 1, 1)
check("DNS 查询包（QR=0，不该当答案）", names.dns_answers(query), [])
check("DNS 截断包", names.dns_answers(b"\x12\x34\x81\x80\x00"), [])

# 指针自指的畸形包：必须返回空而不是死循环
loop = struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + b"\x01\x02\x03\x04"
check("DNS 畸形（答案名指向自己）不死循环", names.dns_answers(loop), [])

# ---------------------------------------------------------------- TLS SNI
check("ClientHello 的 SNI", names.tls_sni(build_client_hello("cdn.example.com")), "cdn.example.com")
check("ClientHello（无 SNI 扩展）", names.tls_sni(build_client_hello(None)), None)
check("ClientHello（首包被截断）", names.tls_sni(build_client_hello("a.b.com", truncated=True)), None)
check("非 TLS 载荷", names.tls_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None)
check("大写域名归一化", names.tls_sni(build_client_hello("Example.COM.")), "example.com")
check("预筛函数认同真 ClientHello", names.looks_like_client_hello(build_client_hello("x.com")), True)
check("预筛函数拒绝 HTTP", names.looks_like_client_hello(b"GET / HTTP/1.1"), False)

# ---------------------------------------------------------------- 解析器
resolver = names.NameResolver()
resolver.note_dns("example.com", "93.184.216.34")
resolver.note_sni("93.184.216.34", 443, "www.example.com")
check("SNI 优先于 DNS", resolver.describe("93.184.216.34:443"), {"name": "www.example.com", "source": "sni"})
check("同 IP 其他端口退回 DNS", resolver.describe("93.184.216.34:8443"), {"name": "example.com", "source": "dns"})
check("未知 IP → None", resolver.describe("8.8.8.8:443"), None)

expiring = names.NameResolver(dns_ttl=0.0, sni_ttl=0.0)
expiring.note_dns("a.com", "1.1.1.1")
check("TTL 到期后不再返回", expiring.describe("1.1.1.1:80"), None)

big = names.NameResolver()
for index in range(names.MAX_CACHE + 200):
    big.note_dns(f"h{index}.com", f"10.{index // 256}.{index % 256}.1")
check("缓存有界（超过上限后仍 <= MAX_CACHE）", len(big._by_ip) <= names.MAX_CACHE, True)  # noqa: SLF001
print(f"\n统计: {resolver.stats()}")

print(f"\n{'全部通过' if not FAILURES else '失败项: ' + ', '.join(FAILURES)}")
raise SystemExit(1 if FAILURES else 0)
