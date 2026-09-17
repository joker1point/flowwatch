"""单条流深挖：未归因流到底处于连接的哪个阶段？为什么表里没有它？

背景：残余未归因流按字节 **98% 是 TCP**，且"本机当 NAT 网关转发"假设已被提权实测证伪。
于是最后的问题只剩一句：**这些 TCP 流的本地端口为什么从不出现在连接表里**。

这次的做法与上一次（事后查表，被对照组否决）不同：
  1. 采集层现在会给每条未归因流记 **TCP 标志位指纹**（S 握手 / A 确认 / P 数据 / R 复位 / F 结束）；
  2. 本探针在**流还活动时就查表**（连续 3 次、跨 1.5 秒），而不是 40 秒之后才查 ——
     上一版失败的根因就是"事后查表必然查不到"（对照组只有 39~44% 命中）；
  3. 按标志位分组汇报：握手期 / 数据期 / 拆除期，各自的查表命中率分别是多少。

用法：`python scripts/single_flow_probe.py [秒数]`（**不需要管理员**）
"""
import json
import socket
import sys
import time
import urllib.request
from collections import Counter, defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                       # noqa: BLE001
    pass

SECONDS = int(sys.argv[1]) if len(sys.argv) > 1 else 90
BASE = "http://127.0.0.1:8788"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 死代理会劫持回环请求

import psutil                                           # noqa: E402


def api(path: str) -> dict:
    with OPENER.open(BASE + path, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def local_ips() -> set:
    out = set()
    for _name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                out.add(addr.address)
            elif addr.family == socket.AF_INET6:
                out.add(addr.address.split("%")[0].lower())
    return out


def split_endpoint(text: str) -> tuple[str, int]:
    text = text.strip()
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
    else:
        host, _, port = text.rpartition(":")
    try:
        return host.lower(), int(port or 0)
    except ValueError:
        return host.lower(), 0


def snapshot() -> tuple[set[tuple[str, int, str, int]], dict[tuple[str, int], tuple[str, int]], set[tuple[str, int]]]:
    """(精确四元组, 本地端口 → (state, pid), 远端 (ip,port) 集合)"""
    exact, by_local, remotes = set(), {}, set()
    for conn in psutil.net_connections(kind="inet"):
        l = (str(conn.laddr.ip).lower(), conn.laddr.port) if conn.laddr else None
        r = (str(conn.raddr.ip).lower(), conn.raddr.port) if conn.raddr else None
        if l:
            by_local[l] = (conn.status, conn.pid)
        if r:
            remotes.add(r)
        if l and r:
            exact.add((l[0], l[1], r[0], r[1]))
            exact.add((r[0], r[1], l[0], l[1]))          # 两个方向都算命中
    return exact, by_local, remotes


def proc_name(pid: int | None) -> str:
    if not pid:
        return "—"
    try:
        return f"{psutil.Process(pid).name()}({pid})"
    except Exception:                                   # noqa: BLE001
        return f"pid {pid}"


print("=" * 78)
print(f"单条流深挖   采样 {SECONDS}s   目标 {BASE}")
print("=" * 78)

locals_set = local_ips()
seen: dict[str, dict] = {}          # flow → {signs, bytes, packets, windows}
print("开始采样（每 0.5 秒一帧，对持续出现的流做即时查表）…\n")

deadline = time.time() + SECONDS
while time.time() < deadline:
    try:
        frame = api("/api/rates?limit=1")
    except Exception:                                   # noqa: BLE001
        time.sleep(0.5)
        continue
    for item in frame.get("unknown_flows") or []:
        flow = item.get("flow") or ""
        if " → " not in flow:
            continue
        slot = seen.setdefault(flow, {"signs": set(), "bytes": 0, "packets": 0, "windows": 0, "probe": None})
        slot["signs"].update(item.get("signs") or "")
        slot["bytes"] += int(item.get("out_bytes") or 0) + int(item.get("in_bytes") or 0)
        slot["packets"] += int(item.get("packets") or 0)
        slot["windows"] += 1
        # 流出现 3 个窗口以上（说明它还在活动）→ 立刻查表（连续 3 次，跨 1.5s）
        if slot["windows"] == 3 and slot["probe"] is None:
            src, dst = flow.split(" → ", 1)
            s_ip, s_port = split_endpoint(src)
            d_ip, d_port = split_endpoint(dst)
            if s_ip in locals_set:
                l_ip, l_port, r_ip, r_port = s_ip, s_port, d_ip, d_port
            else:
                l_ip, l_port, r_ip, r_port = d_ip, d_port, s_ip, s_port
            hits = {"exact": 0, "local_port": 0, "remote": 0}
            detail = "（未命中）"
            for _ in range(3):
                exact, by_local, remotes = snapshot()
                if (l_ip, l_port, r_ip, r_port) in exact:
                    hits["exact"] += 1
                if (l_ip, l_port) in by_local:
                    hits["local_port"] += 1
                    state, pid = by_local[(l_ip, l_port)]
                    detail = f"{state} · {proc_name(pid)}"
                if (r_ip, r_port) in remotes:
                    hits["remote"] += 1
                time.sleep(0.5)
            slot["probe"] = {**hits, "detail": detail,
                             "lport": l_port, "rip": r_ip, "rport": r_port}
    time.sleep(0.2)

probed = [f for f, s in seen.items() if s["probe"]]
print(f"采样结束：未归因流 {len(seen)} 条，其中持续出现并做过即时查表 {len(probed)} 条\n")

print("【按 TCP 标志位分组：这类流在表里的命中情况】")
groups: dict[str, list] = defaultdict(list)
for flow, slot in seen.items():
    if not slot["probe"]:
        continue
    signs = "".join(sorted(slot["signs"])) or "（无/UDP）"
    groups[signs].append((flow, slot))
print(f"  {'标志位':<12}{'流数':>5}{'字节':>10}   即时查表命中(精确/同本地端口/同远端)")
for signs, items in sorted(groups.items(), key=lambda kv: -sum(s["bytes"] for _, s in kv[1])):
    h = [s["probe"] for _, s in items]
    exact = sum(1 for x in h if x["exact"])
    lp = sum(1 for x in h if x["local_port"])
    rm = sum(1 for x in h if x["remote"])
    total = sum(s["bytes"] for _, s in items)
    print(f"  {signs:<12}{len(items):>5}{total / 1024:>8.1f}K   {exact}/{len(items)} · {lp}/{len(items)} · {rm}/{len(items)}")

print("\n【样本细节（每类最多 5 条）】")
for signs, items in sorted(groups.items(), key=lambda kv: -sum(s["bytes"] for _, s in kv[1])):
    print(f"\n  标志位 {signs}:")
    for flow, slot in sorted(items, key=lambda kv: -kv[1]["bytes"])[:5]:
        p = slot["probe"]
        print(f"    {flow:<46} {slot['bytes'] / 1024:>7.1f}K  "
              f"命中 精确{p['exact']}/3 同端口{p['local_port']}/3 同远端{p['remote']}/3  → {p['detail']}")

print("\n【怎么读】")
print("  · 只见 S/SA（握手期）→ 连接是我们开始观测之后才建的，表本该抓到 → miss 是**索引时效**问题；")
print("  · 只见 PA（数据期）→ 连接早已建立，若表仍查不到 → 要查**连接表为什么缺这条目**；")
print("  · 只见 R/F（拆除期）→ 连接正在关闭，本来就没有 socket，**不是缺陷**；")
print("  · 只有 R 且来自远端 → 别人在连我们不存在的端口，同样**不是缺陷**（可考虑单独出账）。")
print("\nSINGLE FLOW PROBE DONE")
