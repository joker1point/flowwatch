"""证据脚本：证明：绕过本层、用系统 logman 采同一 provider，9 秒得到 73981 条 Kernel-Network 事件（tracerpt 转 CSV 核对）。
结论：provider、权限、会话都正常，数据源没有问题。

（本文件是 6 轮提权诊断实验的一环，保留下来是为了让 README 的结论可复核。）
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUN = REPO / "_run"
ETL = RUN / "flowwatch-etl.etl"
CSV = RUN / "flowwatch-etl.csv"
SESSION = "flowwatch-etl"
PROVIDER = "Microsoft-Windows-Kernel-Network"


def run(*args: str) -> tuple[int, str]:
    proc = subprocess.run(args, capture_output=True, text=True, errors="replace")
    output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    return proc.returncode, output


def main() -> int:
    RUN.mkdir(parents=True, exist_ok=True)
    for path in (ETL, CSV):
        if path.exists():
            path.unlink()

    # 背景真实流量：保证有连接事件可采（短连接正是目标场景）
    traffic = subprocess.Popen(
        [sys.executable, str(REPO / "tools" / "traffic.py"), "--seconds", "45", "--interval", "1"],
        cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(3)

    code, out = run("logman", "start", SESSION, "-p", PROVIDER, "0x30", "4", "-o", str(ETL), "-ets")
    print(f"logman start → rc={code} {out}", flush=True)
    time.sleep(9)
    code, out = run("logman", "stop", SESSION, "-ets")
    print(f"logman stop  → rc={code} {out}", flush=True)
    traffic.terminate()

    if not ETL.exists():
        print("ETL 未生成 → 连 logman 都采不到：provider 在本环境下不产事件", flush=True)
        return 0
    print(f"ETL 大小 {ETL.stat().st_size} 字节", flush=True)

    code, out = run("tracerpt", str(ETL), "-o", str(CSV), "-of", "CSV", "-y")
    print(f"tracerpt → rc={code} {out.splitlines()[-1] if out else ''}", flush=True)
    if not CSV.exists():
        print("CSV 未生成", flush=True)
        return 0

    rows = CSV.read_text(encoding="utf-8", errors="replace").splitlines()
    kernel = [row for row in rows if "Kernel-Network" in row]
    print(f"CSV 行数 {len(rows)} · 含 Kernel-Network 的行 {len(kernel)}", flush=True)
    for row in kernel[:3]:
        print("  样例: " + row[:240], flush=True)

    print("\n判读：" + ("ETL 里有事件 → 会话/provider 正常，问题在我的 ProcessTrace 消费端"
                       if kernel else "ETL 里没有事件 → provider 在该环境下不产事件，应改数据源"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
