"""验证假设：残余未归因流是**本机转发的流量**（虚拟机 / WSL / 容器 / NAT），宿主上没有对应 socket。

为什么这个假设最合理：三条证据指向同一处 ——
  · 早期 `diag_miss.py`/`diag_race.py`：未归因流的本地端口**从不出现在连接表里**（79.5%，165ms 轮询也抓不到）；
  · 今天的近邻诊断：连 ETW（TCP+UDP 事件）学到的键也覆盖不到这批流；
  · 形态：`163.177.46.106:443 → 10.44.99.5:49748` —— 外网与本地 LAN 地址直接对话，
    而 NAT 转发（WinNAT/ICS）会把源改写成宿主地址、且**端口归内核 NAT 所有，不属任何用户态 socket**。
若成立，这就是"连接表 + PID"类方法的**原理性边界**，不是归因缺陷。

判据（**自带对照组**，避免自欺）：
  1. 采样 `/api/rates`：未归因流（`unknown_flows`）与已归因连接（`by_pid[].conns[].remote`）；
  2. 对未归因流的**本地端口**去 `psutil.net_connections()` 查 socket —— 假设成立则应**查不到**；
  3. **对照组**：已归因连接的远端 `ip:port` 应当能在表里查到（查不到就说明检测方法有问题，结论作废）；
  4. 附加证据：虚拟网卡与网段、`winnat`/`SharedAccess` 服务状态、未归因 IP 是否落在虚拟网段内。

用法：`python scripts/forwarding_hypothesis_probe.py [秒数]`（**不需要管理员**）
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from collections import Counter

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                       # noqa: BLE001
    pass

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 90
BASE = "http://127.0.0.1:8788"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 绕开环境里那个死代理


def api(path: str) -> dict:
    with OPENER.open(BASE + path, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def split_endpoint(text: str) -> tuple[str, int]:
    """`1.2.3.4:443` / `[::1]:443` → (ip, port)。"""
    text = text.strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
        return host.lower(), int(port or 0)
    host, _, port = text.rpartition(":")
    return host.lower(), int(port or 0)


def sockets_now() -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
    """(本机侧 (ip,port) 集合, 远端侧 (ip,port) 集合) —— 含 TCP/UDP 全状态。"""
    import psutil
    local, remote = set(), set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port:
            local.add((str(conn.laddr.ip).lower(), conn.laddr.port))
        if conn.raddr and conn.raddr.port:
            remote.add((str(conn.raddr.ip).lower(), conn.raddr.port))
    return local, remote


def virtual_nets() -> list[tuple[str, str, str]]:
    """(网卡名, 地址, 网段前缀) —— 顺便把虚拟网卡名单独标出来。"""
    import psutil
    out = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address:
                netmask = addr.netmask or ""
                try:
                    prefix = socket.inet_ntoa(bytes(int(a) & int(b) for a, b in
                                                    zip(socket.inet_aton(addr.address), socket.inet_aton(netmask))))
                except OSError:
                    prefix = addr.address
                out.append((name, addr.address, f"{prefix}/{sum(bin(int(x)).count('1') for x in netmask.split('.'))}"))
    return out


VIRTUAL_HINTS = ("vethernet", "wsl", "docker", "hyper-v", "vmware", "virtualbox", "tailscale", "loopback",
                 "bluetooth", "npcap", "loopback", "tap", "tun", "zerotier", "radmin")


def service_state(name: str) -> str:
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              f"(Get-Service -Name {name} -ErrorAction SilentlyContinue).Status"],
                             capture_output=True, text=True, timeout=20, errors="replace")
        return (out.stdout or "").strip() or "（服务不存在）"
    except Exception as exc:                            # noqa: BLE001
        return f"查询失败: {exc}"


print("=" * 78)
print(f"转发流量假设验证   采样 {SECONDS}s   目标 {BASE}")
print("=" * 78)

# ── 1. 采样两组流 ────────────────────────────────────────────────────────────
unknown: dict[str, dict] = {}
attributed_remote: dict[tuple[str, int], int] = {}
errors = 0
for i in range(SECONDS):
    try:
        frame = api("/api/rates?limit=50")
    except Exception:                                   # noqa: BLE001
        errors += 1
        time.sleep(1)
        continue
    for item in (frame.get("unknown_flows") or []):
        flow = item.get("flow") or ""
        if " → " in flow:
            src, dst = flow.split(" → ", 1)
            key = f"{src.strip()} → {dst.strip()}"
            slot = unknown.setdefault(key, {"src": src.strip(), "dst": dst.strip(), "packets": 0, "bytes": 0})
            slot["packets"] += int(item.get("packets") or 0)
            slot["bytes"] += int(item.get("out_bytes") or 0) + int(item.get("in_bytes") or 0)
    for row in frame.get("by_pid") or []:
        for conn in row.get("conns") or []:
            try:
                remote = split_endpoint(conn["remote"])
                attributed_remote[remote] = attributed_remote.get(remote, 0) + 1
            except Exception:                           # noqa: BLE001
                pass
    time.sleep(1)

print(f"采样完成：未归因流 {len(unknown)} 条（去重后）· 已归因远端 {len(attributed_remote)} 个 · 采样失败 {errors} 次")

# ── 2. 查 socket 表 ─────────────────────────────────────────────────────────
local_socks, remote_socks = sockets_now()
print(f"当前 socket 表：本机侧 {len(local_socks)} 个 (ip,port) · 远端侧 {len(remote_socks)} 个\n")

hit_local, miss_local = [], []
for flow, info in unknown.items():
    ip, port = split_endpoint(info["dst"])              # 未归因流里 dst 可能是本机侧，也可能是远端
    if port and (ip, port) in local_socks:
        hit_local.append((flow, info))
        continue
    ip2, port2 = split_endpoint(info["src"])
    if port2 and (ip2, port2) in local_socks:
        hit_local.append((flow, info))
    else:
        miss_local.append((flow, info))

# 协议分布：残缺口里 TCP 与 UDP 的可归因性完全不同（TCP 有 connect/accept 事件，UDP 只有逐数据报事件）
proto_split: Counter = Counter()
proto_bytes: Counter = Counter()
for flow, info in unknown.items():
    name = flow.split(" ", 1)[0] if flow[:4] in ("tcp ", "udp ") else "（旧格式/未知）"
    proto_split[name] += 1
    proto_bytes[name] += info["bytes"]
print("【未归因流的协议分布（决定“能不能归”的类别）】")
for name, num in proto_split.most_common():
    print(f"  {name:<14} {num:>4} 条 · {proto_bytes[name] / 1024:>9.1f} KiB")
print()

print("【未归因流：本机侧端口能否在 socket 表里找到？】")
print(f"  找到   {len(hit_local):>4} 条（{len(hit_local) / max(1, len(unknown)) * 100:.0f}%）")
print(f"  找不到 {len(miss_local):>4} 条（{len(miss_local) / max(1, len(unknown)) * 100:.0f}%）  ← 假设成立的话，这里应当占绝大多数")

print("\n【对照组：已归因连接的远端能否在 socket 表里找到？】")
ctrl_hit = sum(1 for ep, _ in attributed_remote.items() if ep in remote_socks)
ctrl_total = len(attributed_remote)
print(f"  远端命中 {ctrl_hit}/{ctrl_total}（{ctrl_hit / max(1, ctrl_total) * 100:.0f}%）"
      f"   ← 若这个比例也很低，说明**检测方法本身不可靠**，上面的结论不成立")

if miss_local:
    print("\n【找不到 socket 的未归因流 · Top 10（按字节）】")
    for flow, info in sorted(miss_local, key=lambda kv: -kv[1]["bytes"])[:10]:
        print(f"  {flow:<48} {info['packets']:>5} 包 {info['bytes'] / 1024:>8.1f} KiB")

# ── 3. 虚拟网段与服务 ───────────────────────────────────────────────────────
print("\n【本机网卡与网段（虚拟网卡标 ★）】")
nets = virtual_nets()
for name, addr, cidr in nets:
    star = "★" if any(h in name.lower() for h in VIRTUAL_HINTS) else " "
    print(f"  {star} {name:<28} {addr:<16} {cidr}")

def in_any_virtual(ip: str) -> str | None:
    for name, _addr, cidr in nets:
        if not any(h in name.lower() for h in VIRTUAL_HINTS):
            continue
        prefix, _, bits = cidr.partition("/")
        try:
            if (socket.inet_aton(ip)[: int(bits) // 8] == socket.inet_aton(prefix)[: int(bits) // 8]
                    and int(bits) % 8 == 0):
                return name
        except OSError:
            continue
    return None


if miss_local:
    virtual_hits = Counter()
    for flow, info in miss_local:
        for endpoint in (info["src"], info["dst"]):
            ip, _ = split_endpoint(endpoint)
            name = in_any_virtual(ip)
            if name:
                virtual_hits[name] += 1
    print(f"\n  未归因流的 IP 落在虚拟网卡网段内的情况: {dict(virtual_hits) if virtual_hits else '（无）'}")

print("\n【转发相关服务】")
for svc in ("winnat", "SharedAccess", "hns", "vmcompute", "WslService", "com.docker.service"):
    print(f"  {svc:<20} {service_state(svc)}")

print("\n【判定】")
verdict = []
if ctrl_total and ctrl_hit / ctrl_total >= 0.5:
    verdict.append("对照组健康（已归因连接的远端能在表里查到）→ 检测方法可信")
else:
    verdict.append("⚠️ 对照组命中率偏低 → 检测方法不可靠，本次结论**不成立**")
if unknown and len(miss_local) / len(unknown) >= 0.7:
    verdict.append("未归因流绝大多数在 socket 表里**找不到** → 与\"本机转发流量\"假设一致")
else:
    verdict.append("未归因流仍有相当比例能在表里找到 → 假设不成立或只是部分原因")
for line in verdict:
    print("  · " + line)
print("\nFORWARDING PROBE DONE")
