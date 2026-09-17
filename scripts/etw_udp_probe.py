"""dump 一份真实 UDP 事件，**从 XML 里读字段名**（不猜模板）—— 校准 UDP 归因的前置步骤。

为什么这么做：我第一版直接假设"UDP 事件复用连接事件的模板"，实测被现实打脸 ——
69,722 条事件里 66,820 条两侧地址都不属于本机（fail-closed 自停，没误归因）。
教训（09-16 那次的翻版）：**字段语义必须从真实 dump 读**，`tracerpt` 转出来的 XML 带字段名，
是权威且本机可得的来源。

做法（照搬批量路线里已验证的配方）：
  1. logman 起一个 ~8 秒的会话采 `Microsoft-Windows-Kernel-Network`（关键字 0x30 = IPv4|IPv6）
  2. tracerpt 转 XML
  3. 本文只做一件"证据"的事：**把所有事件按 ID 分组，打印每个 ID 的字段名与前若干条的取值**，
     重点是 42/43（UDP 发送/接收）与 58/59（IPv6 镜像），以及我已在用的 12/13/15。

**需要管理员**（创建 ETW 会话）。用法（管理员 PowerShell）：
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\run_elevated.ps1 scripts\\etw_udp_probe.py
"""
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:                                       # noqa: BLE001
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "_run")
ETL = os.path.join(RUN, "udp_probe.etl")
XML = os.path.join(RUN, "udp_probe.xml")
SESSION = "flowwatch-udp-probe"
SECONDS = 8
PROVIDER = "Microsoft-Windows-Kernel-Network"
KEYWORDS = "0x30"


def run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")


def main() -> int:
    os.makedirs(RUN, exist_ok=True)
    for path in (ETL, XML):
        if os.path.exists(path):
            os.remove(path)

    print(f"=== 采 {SECONDS}s（provider={PROVIDER} keywords={KEYWORDS}）===")
    start = run(["logman", "start", SESSION, "-ets", "-p", PROVIDER, KEYWORDS, "5", "-o", ETL, "-f", "bincirc", "-max", "64"])
    if start.returncode != 0:
        print("logman start 失败:", (start.stdout or "") + (start.stderr or ""))
        # 可能是同名会话残留（和 ETW 会话一样的坑），清掉再来一次
        run(["logman", "stop", SESSION, "-ets"])
        time.sleep(1)
        start = run(["logman", "start", SESSION, "-ets", "-p", PROVIDER, KEYWORDS, "5", "-o", ETL, "-f", "bincirc", "-max", "64"])
        if start.returncode != 0:
            print("仍然失败，退出")
            return 1
    time.sleep(SECONDS)
    run(["logman", "stop", SESSION, "-ets"])

    if not os.path.exists(ETL):
        print("没有生成 ETL 文件")
        return 1
    print(f"ETL 大小 {os.path.getsize(ETL) / 1024:.0f} KiB → tracerpt 转 XML …")
    conv = run(["tracerpt", ETL, "-o", XML, "-of", "XML", "-y"], timeout=300)
    if not os.path.exists(XML):
        print("转换失败:", (conv.stdout or "")[-300:] + (conv.stderr or "")[-300:])
        return 1
    print(f"XML 大小 {os.path.getsize(XML) / 1024 / 1024:.1f} MiB")

    # 解析：按 EventID 分组，收集字段名与样例值
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    fields: dict[str, list[str]] = defaultdict(list)
    samples: dict[str, list[dict]] = defaultdict(list)
    counts: Counter = Counter()
    for _event, elem in ET.iterparse(XML, events=("end",)):
        if not elem.tag.endswith("}Event"):
            continue
        sysinfo = elem.find("e:System", ns)
        evdata = elem.find("e:EventData", ns)
        if sysinfo is None or evdata is None:
            elem.clear()
            continue
        evid = (sysinfo.findtext("e:EventID", default="?", namespaces=ns) or "?").strip()
        counts[evid] += 1
        row = {}
        for data in evdata.findall("e:Data", ns):
            name = data.get("Name") or "?"
            if name not in fields[evid]:
                fields[evid].append(name)
            row[name] = (data.text or "").strip()
        if len(samples[evid]) < 3:
            samples[evid].append(row)
        elem.clear()

    print("\n=== 事件 ID 分布（Top 15）===")
    for evid, num in counts.most_common(15):
        names = fields.get(evid, [])
        print(f"  id={evid:<4} {num:>7} 条  字段: {', '.join(names) if names else '(无 EventData)'}")

    print("\n=== 每个 ID 的前 3 条取值（带字段名 —— 这就是校准依据）===")
    for evid in sorted(counts, key=lambda k: -counts[k])[:12]:
        print(f"\n  id={evid}（{counts[evid]} 条）")
        for row in samples[evid]:
            print("    " + "  ".join(f"{k}={v}" for k, v in row.items()))

    print("\n=== 判定：UDP（42/43/58/59）的字段是否与连接事件同构？===")
    for evid in ("42", "43", "58", "59", "12", "13", "15"):
        if evid in counts:
            print(f"  id={evid}: {', '.join(fields[evid])}")
        else:
            print(f"  id={evid}: 本次没采到")
    print("\nUDP PROBE DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
