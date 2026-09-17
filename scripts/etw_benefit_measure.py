"""ETW 实时归因的收益测量：**唯一变量是 ETW 本身**。

设计（避免"测出来的提升其实来自权限，而不是 ETW"这种自欺）：
  · 两阶段都在**提权**下跑同一个 server.py —— 提权本身会顺带改善表归因
    （非提权时 899/5394 条端点拿不到 owning PID，就是"属主受限"那一桶）；
  · 阶段 1：提权 + **不开** ETW      → 基线（含提权红利）
  · 阶段 2：提权 + `--etw`          → 差值就是 ETW 的净贡献
  · 每阶段先热身 15 秒（冷启动偏移），再按 1 秒采样 40 次。

指标：未归因率（均值/中位/最小/最大）、属主受限字节、ETW 状态（events/learned/forgotten）。

需要管理员（ETW 会话）。用法（管理员 PowerShell）：
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\run_elevated.ps1 scripts\\etw_benefit_measure.py
"""
import json
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                          # noqa: BLE001
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # flowwatch/
PORT = 8788
# 可用环境变量缩短（用于非提权演练，验证脚本机制本身）
WARMUP = float(os.environ.get("FW_WARMUP", "15"))
SAMPLES = int(os.environ.get("FW_SAMPLES", "40"))
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 绕开环境里那个死代理（它连回环都劫持）


def api(path: str):
    with OPENER.open(f"http://127.0.0.1:{PORT}{path}", timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def kill_listeners(port: int) -> int:
    """清掉占着端口的进程。

    Windows 允许**两个进程同绑一个端口**（SO_REUSEADDR 假成功），
    请求会落到旧进程上 → 表现为"改了代码但接口还是旧行为"。必须清干净再起新的。
    """
    import psutil
    killed = 0
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status == "LISTEN" and conn.laddr and conn.laddr.port == port and conn.pid:
            if conn.pid == os.getpid():
                continue
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                try:
                    proc.wait(timeout=6)
                except psutil.TimeoutExpired:
                    proc.kill()
                killed += 1
            except Exception:                              # noqa: BLE001
                pass
    if killed:
        time.sleep(1.5)
    return killed


def wait_health(timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if api("/api/health").get("status") in ("ok", "degraded"):
                return True
        except Exception:                                  # noqa: BLE001
            pass
        time.sleep(1.0)
    return False


def start_server(use_etw: bool):
    argv = [sys.executable, "server.py", "--port", str(PORT)]
    if use_etw:
        argv.append("--etw")
    log = open(os.path.join(ROOT, "_run", "server_etw_measure.log"), "ab", buffering=0)
    log.write(f"\n\n===== start {'WITH' if use_etw else 'WITHOUT'} --etw  {time.strftime('%H:%M:%S')} =====\n".encode())
    return subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)


def stop_server(proc) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=8)
    except Exception:                                      # noqa: BLE001
        try:
            proc.kill()
        except Exception:                                  # noqa: BLE001
            pass
    kill_listeners(PORT)


def start_traffic(seconds: float):
    """受控短连接负载（FW_TRAFFIC=1 时启用）。

    整机未归因率由**流量构成**主导（实测同一台机器同一份代码：短连接密集时 ~30%、
    空闲时 <5%）—— 所以“开 ETW 前后”必须在**同样的负载**下比，否则测的是流量差异。
    """
    # **默认就开**：受控负载是这次测量的前提（没有它，两阶段比的只是"两个时段流量不同"）。
    # 注意别用环境变量控制开关 —— UAC 提权会给子进程全新的环境块，传不进去（实测踩到）。
    if os.environ.get("FW_NO_TRAFFIC") == "1":
        return None
    argv = [sys.executable, os.path.join(ROOT, "tools", "traffic.py"),
            "--seconds", str(int(seconds)), "--interval", "1"]
    log = open(os.path.join(ROOT, "_run", "traffic_measure.log"), "ab", buffering=0)
    log.write(("\n===== traffic start " + time.strftime("%H:%M:%S") + " =====\n").encode())
    return subprocess.Popen(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)


def phase(label: str, use_etw: bool) -> dict:
    print(f"\n===== {label}（{'--etw' if use_etw else '不开 ETW'}）=====")
    kill_listeners(PORT)
    proc = start_server(use_etw)
    if not wait_health():
        print("  服务没起来，跳过这一阶段")
        stop_server(proc)
        return {}
    traffic = start_traffic(WARMUP + SAMPLES + 6)
    gen_pid = traffic.pid if traffic else None      # 受控负载自己的 PID：看它被归因了多少
    print(f"  服务已就绪，热身 {WARMUP:.0f}s …" + ("（同时跑受控短连接负载）" if traffic else ""))
    time.sleep(WARMUP)

    ratios, masked, foreign, skipped, rolling = [], [], [], [], []
    etw_stat, hits = {}, {}
    last_flows: list = []
    gen_bps: list[float] = []                       # 受控负载被归因到自己的速率
    for i in range(SAMPLES):
        try:
            frame = api("/api/rates?limit=10")
            totals = frame["totals"]
            last_flows = frame.get("unknown_flows") or last_flows
            if gen_pid is not None:
                gen_bps.append(sum(float(r["out_bps"]) + float(r["in_bps"])
                                   for r in frame["by_pid"] if r["pid"] == gen_pid))
            ratios.append(float(totals["unknown_ratio"]))
            masked.append(float(totals["masked_bytes"]))
            foreign.append(float(totals["foreign_packets"]))
            skipped.append(float(totals["skipped_packets"]))
            if "unknown_ratio_rolling" in totals:          # 滚动值比逐窗口稳定，一并记下来
                rolling.append(float(totals["unknown_ratio_rolling"]))
        except Exception as exc:                           # noqa: BLE001
            print(f"    采样 {i} 失败: {exc}")
        if i == SAMPLES - 1:
            try:
                health = api("/api/health")
                etw_stat = health.get("etw", {})
                hits = {"sticky": health.get("sticky_hits"), "memory": health.get("memory_hits"),
                        "masked_bytes": health.get("masked_bytes")}
            except Exception:                              # noqa: BLE001
                pass
        time.sleep(1.0)

    if not ratios:
        stop_server(proc)
        return {}
    # 受控负载被归因了多少字节：走**历史层**（按全部 pid 落库），不用 by_pid（被 TOP_N 截断）
    gen_hist: dict = {}
    if gen_pid is not None:
        try:
            hist = api(f"/api/history/process?pid={gen_pid}&minutes=5&bucket=1")
            gen_hist = {"bytes": hist.get("total_bytes", 0), "buckets": len(hist.get("series") or [])}
        except Exception as exc:                       # noqa: BLE001
            gen_hist = {"error": f"{type(exc).__name__}: {exc}"}
    out = {
        "mean": statistics.mean(ratios) * 100,
        "median": statistics.median(ratios) * 100,
        "min": min(ratios) * 100,
        "max": max(ratios) * 100,
        "masked_kib": statistics.mean(masked) / 1024.0,
        "foreign_pkts": statistics.mean(foreign),
        "skipped_pkts": statistics.mean(skipped),
        "etw": etw_stat,
        "hits": hits,
        "flows": last_flows[:5],
        "gen_kib_s": (statistics.mean(gen_bps) / 1024.0) if gen_bps else 0.0,
        "gen_hist": gen_hist,
    }
    print(f"  未归因率: 均值 {out['mean']:.1f}% · 中位 {out['median']:.1f}% · "
          f"最小 {out['min']:.1f}% · 最大 {out['max']:.1f}%")
    print(f"  属主受限(均值): {out['masked_kib']:.1f} KiB/窗口")
    if hits:
        print(f"  兜底命中(累计): 端点短时记忆 {hits.get('sticky')} / 四元组记忆 {hits.get('memory')}")
    if gen_hist:
        if "bytes" in gen_hist:
            print(f"  受控负载被归因（历史层累计）: {gen_hist['bytes'] / 1024:.1f} KiB "
                  f"/ {gen_hist['buckets']} 个分钟桶") 
        else:
            print(f"  受控负载历史查询失败: {gen_hist.get('error')}")
    if gen_bps:
        print(f"  （参考）受控负载在 Top-N 排行里的速率: 均值 {out['gen_kib_s']:.1f} KiB/s")
    if last_flows:
        print("  未归因流 Top5（ETW 生效时应变少或消失）:")
        for item in last_flows[:5]:
            print(f"    {item['flow']:<46} {item['packets']:>5} 包  "
                  f"{(item['out_bytes'] + item['in_bytes']) / 1024:>8.1f} KiB")
    if etw_stat:
        print(f"  ETW: state={etw_stat.get('state')} events={etw_stat.get('events')} "
              f"learned={etw_stat.get('learned')} forgotten={etw_stat.get('forgotten')} "
              f"sanity_failures={etw_stat.get('sanity_failures')}")
        if etw_stat.get("detail"):
            print(f"       detail={etw_stat['detail']}")
    if traffic:
        traffic.terminate()
        try:
            traffic.wait(timeout=6)
        except Exception:                              # noqa: BLE001
            traffic.kill()
    stop_server(proc)
    return out


print("=" * 78)
print(f"ETW 收益测量   port={PORT}   warmup={WARMUP:.0f}s   samples={SAMPLES}")
print("=" * 78)

base = phase("阶段 1 · 提权基线", use_etw=False)
with_etw = phase("阶段 2 · 提权 + ETW 实时归因", use_etw=True)

print("\n" + "=" * 78)
print("【结论】")
if base and with_etw:
    print(f"  未归因率 均值: {base['mean']:.1f}%  ->  {with_etw['mean']:.1f}%   "
          f"（变化 {with_etw['mean'] - base['mean']:+.1f} 个百分点）")
    print(f"  未归因率 中位: {base['median']:.1f}%  ->  {with_etw['median']:.1f}%   "
          f"（变化 {with_etw['median'] - base['median']:+.1f} 个百分点）")
    print(f"  属主受限    : {base['masked_kib']:.1f} KiB  ->  {with_etw['masked_kib']:.1f} KiB")
    etw = with_etw.get("etw") or {}
    print(f"  ETW 净贡献  : state={etw.get('state')} learned={etw.get('learned')} "
          f"forgotten={etw.get('forgotten')} sanity_failures={etw.get('sanity_failures')}")
    print("  说明：两阶段都在提权下，所以差值只归因于 ETW 本身。")
    print("  【关键指标】受控负载（短命连接）被归因的字节 —— 历史层统计，不受 Top-N 截断：")
    base_bytes = (base.get("gen_hist") or {}).get("bytes", 0)
    etw_bytes = (with_etw.get("gen_hist") or {}).get("bytes", 0)
    print(f"    不开 ETW: {base_bytes / 1024:.1f} KiB   →   开 ETW: {etw_bytes / 1024:.1f} KiB")
    if etw_bytes > base_bytes * 1.5 and etw_bytes > 0:
        print("    → ETW 确实把表抓不到的短命连接补上了（这是它存在的理由）")
    elif etw_bytes > base_bytes:
        print("    → 方向一致但差距不显著，别急着下结论（加大负载/延长采样再测）")
    else:
        print("    → 没看出 ETW 的贡献：要么表已覆盖这些连接，要么 ETW 没真正生效（先看 state）")
    print(f"  （参考）未归因流条数: 基线 {len(base.get('flows') or [])} → 开 ETW "
          f"{len(with_etw.get('flows') or [])}；两阶段连接本就不同，别只看这个）")
else:
    print("  数据不全（服务没起来 / 采样失败），结论：本次不成立，别硬解释。")
print("=" * 78)
print("MEASURE DONE")
