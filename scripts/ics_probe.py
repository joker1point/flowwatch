r"""验证假设：这台机器在当 **NAT 网关**（ICS / WinNAT），转发的流量以宿主地址出现、
没有宿主 socket、也没有带 PID 的 ETW 连接事件 —— 那正是残余未归因流的来源。

为什么这条假设最自洽（三条观测同时吻合）：
  · 165 ms 高频采样也查不到那些本地端口 → 宿主上没有 socket；
  · ETW（TCP+UDP 事件）学到的键里没有同端口候选 → 不是用户态连接；
  · 残余未归因流 **98% 是 TCP** → 不是 QUIC/UDP 那类小流。

判据（按可信度从强到弱）：
  1. **IP 转发开关**：`Get-NetIPInterface | ? Forwarding -eq Enabled` —— 直接证据；
  2. **WinNAT 会话**：`Get-NetNatSession` 里若出现未归因流的本地端口 → 它就是被转发的；
  3. ICS 配置（注册表 `SharedAccess\Parameters\ScopeAddress`、`EnableICS`）与服务状态；
  4. 网卡清单（虚拟网卡 = 可能的内网侧）。

**需要管理员**。用法（管理员 PowerShell）：
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\run_elevated.ps1 scripts\\ics_probe.py
"""
import json
import re
import subprocess
import sys
import time
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                       # noqa: BLE001
    pass

BASE = "http://127.0.0.1:8788"
SAMPLE_SECONDS = 25
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 死代理会把回环请求也劫持走


def ps(cmd: str) -> str:
    out = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                         capture_output=True, text=True, timeout=90, errors="replace")
    return ((out.stdout or "") + (out.stderr or "")).strip()


def api(path: str) -> dict:
    with OPENER.open(BASE + path, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


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


print("=" * 78)
print("ICS / WinNAT 转发假设验证（管理员）")
print("=" * 78)

print("\n【1】IP 转发开关（最直接：Enabled 就说明这台机器在转发别人的流量）")
print(ps("Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | "
         "Select-Object InterfaceAlias,AddressFamily,Forwarding | Format-Table -AutoSize | Out-String") or
      "（没有开启转发的接口）")

print("\n【2】服务状态")
print(ps("Get-Service -Name SharedAccess,winnat,hns,vmcompute,WslService -ErrorAction SilentlyContinue | "
         "Select-Object Name,Status,StartType | Format-Table -AutoSize | Out-String"))

print("\n【3】ICS 配置（注册表）")
print(ps("$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters'; "
         "if (Test-Path $p) { (Get-ItemProperty $p | Select-Object ScopeAddress,StandaloneDhcpAddress | "
         "Format-List | Out-String) } else { '（无 SharedAccess\\Parameters 键 → ICS 未配置过）' }"))
print(ps("$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedAccess'; "
         "if (Test-Path $p) { 'EnableICS=' + (Get-ItemProperty $p -ErrorAction SilentlyContinue).EnableICS } "
         "else { '（无 EnableICS 键）' }"))

print("\n【4】WinNAT（Hyper-V / WSL 用的 NAT）")
print(ps("$ErrorActionPreference='SilentlyContinue'; "
         "(Get-NetNat | Select-Object Name,InternalIPInterfaceAddressPrefix | Format-Table -AutoSize | Out-String); "
         "if (-not (Get-NetNat)) { '（没有 WinNAT 实例）' }"))

print("\n【5】网卡清单（虚拟网卡 = 可能的内网侧）")
print(ps("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
         "Select-Object Name,InterfaceDescription,LinkSpeed,MacAddress | Format-Table -AutoSize | Out-String"))

# ── 6. 与实时未归因流对照 ───────────────────────────────────────────────────
print(f"\n【6】实时未归因流（采样 {SAMPLE_SECONDS}s）与 NAT 会话对照")
flows: dict[str, int] = {}
for _ in range(SAMPLE_SECONDS):
    try:
        frame = api("/api/rates?limit=1")
        for item in frame.get("unknown_flows") or []:
            flow = item.get("flow") or ""
            if " → " not in flow:
                continue
            src, dst = flow.split(" → ", 1)
            flows[f"{src.strip()} → {dst.strip()}"] = flows.get(f"{src.strip()} → {dst.strip()}", 0) + int(
                item.get("out_bytes") or 0) + int(item.get("in_bytes") or 0)
    except Exception:                                   # noqa: BLE001
        pass
    time.sleep(1)

ports = set()
for flow in flows:
    for endpoint in flow.split(" → "):
        _ip, port = split_endpoint(endpoint)
        if port:
            ports.add(port)
print(f"  未归因流 {len(flows)} 条，涉及本地/远端端口 {len(ports)} 个")

nat_out = ps("(Get-NetNatSession | Select-Object -ExpandProperty LocalPort)")
nat_ports = {int(p) for p in re.findall(r"\d+", nat_out)}
if nat_ports:
    matched = ports & nat_ports
    print(f"  WinNAT 会话端口 {len(nat_ports)} 个；与未归因流端口**重合 {len(matched)} 个**")
    if matched:
        print(f"  重合端口样例: {sorted(matched)[:10]}")
else:
    print("  （没有 WinNAT 会话 —— WinNAT 不是转发来源，或没被启用）")

print("\n【判定】")
forwarding = "Enabled" in ps("(Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | Measure-Object).Count")
count = ps("(Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | Measure-Object).Count").strip()
print(f"  开启转发的接口数: {count or 0}")
if count and count != "0":
    print("  → **这台机器确实在转发 IP** —— 与\"未归因流没有宿主 socket\"完全吻合，假设成立。")
elif nat_ports and (ports & nat_ports):
    print("  → IP 转发开关未开，但未归因流端口落在 WinNAT 会话里 → 转发假设**部分成立**。")
else:
    print("  → **没有找到转发证据**：IP 转发未开、WinNAT 无会话 → 假设**不成立**，残余缺口另有原因，")
    print("     应回到\"为什么这些 TCP 端口从不出现在连接表里\"继续查（这段已如实写进 README）。")
print("\nICS PROBE DONE")
