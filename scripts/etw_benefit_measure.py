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


def phase(label: str, use_etw: bool) -> dict:
    print(f"\n===== {label}（{'--etw' if use_etw else '不开 ETW'}）=====")
    kill_listeners(PORT)
    proc = start_server(use_etw)
    if not wait_health():
        print("  服务没起来，跳过这一阶段")
        stop_server(proc)
        return {}
    print(f"  服务已就绪，热身 {WARMUP:.0f}s …")
    time.sleep(WARMUP)

    ratios, masked, foreign, skipped, rolling = [], [], [], [], []
    etw_stat = {}
    for i in range(SAMPLES):
        try:
            frame = api("/api/rates?limit=1")
            totals = frame["totals"]
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
            except Exception:                              # noqa: BLE001
                pass
        time.sleep(1.0)

    if not ratios:
        stop_server(proc)
        return {}
    out = {
        "mean": statistics.mean(ratios) * 100,
        "median": statistics.median(ratios) * 100,
        "min": min(ratios) * 100,
        "max": max(ratios) * 100,
        "masked_kib": statistics.mean(masked) / 1024.0,
        "foreign_pkts": statistics.mean(foreign),
        "skipped_pkts": statistics.mean(skipped),
        "etw": etw_stat,
    }
    print(f"  未归因率: 均值 {out['mean']:.1f}% · 中位 {out['median']:.1f}% · "
          f"最小 {out['min']:.1f}% · 最大 {out['max']:.1f}%")
    print(f"  属主受限(均值): {out['masked_kib']:.1f} KiB/窗口")
    if etw_stat:
        print(f"  ETW: state={etw_stat.get('state')} events={etw_stat.get('events')} "
              f"learned={etw_stat.get('learned')} forgotten={etw_stat.get('forgotten')} "
              f"sanity_failures={etw_stat.get('sanity_failures')}")
        if etw_stat.get("detail"):
            print(f"       detail={etw_stat['detail']}")
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
    print("  说明：两阶段都在提权下，所以差值只归因于 ETW 本身；"
          "阶段 1 相对非提权基线的改善属于权限红利。")
else:
    print("  数据不全（服务没起来 / 采样失败），结论：本次不成立，别硬解释。")
print("=" * 78)
print("MEASURE DONE")
