#!/usr/bin/env python3
"""无 Npcap 时的降级契约：**页面必须照开**（曾经不是 —— 2026-09-23 真实用户反馈）。

真事故：朋友机器没装 Npcap，双击 exe 后浏览器死活打不开。
根因不在浏览器：`run.py` 先打印"在此之前界面能打开，但不会有流量数据"，紧接着
`import server` 就在**模块级**构造 `Capturer()`，而 `Capturer.__init__` 里
`self.pcap = Pcap()` 会**立刻**加载 wpcap.dll → 抛 PcapError → 进程退出，
uvicorn 从来没起来（崩溃栈：run.py:125 → server.py:225 → collector.py:740 → collector.py:98）。

这条测试**不需要真的卸载 Npcap**：在子进程里挂一个 sitecustomize.py，把
`ctypes.WinDLL("wpcap.dll")` 换成 OSError —— 与"没装时"完全同一条异常路径
（顺带把本就不存在的 iphlpapi 也变成 OSError，WinEndpointTable 会照设计退回 psutil）。

断言（任一失败即红）：
  1. 服务进程**还活着**（没被采集层拖死）；
  2. `/api/health` 返回 200，且 `status == "degraded"`；
  3. `error` 里说明是 Npcap/wpcap 的问题（页面/接口要能告诉用户"去装驱动"，而不是白屏）；
  4. 若有前端构建产物，用 `run.py` 启动时 `/` 必须返回 HTML（= 用户真能看到页面）。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILURES: list[str] = []

SITECUSTOMIZE = '''"""测试注入：模拟"这台机器没装 Npcap"。"""
import ctypes


def _fake_windll(name, *args, **kwargs):
    real = getattr(ctypes, "_fw_real_windll", None)
    if real is not None and not (isinstance(name, str) and name.lower().startswith("wpcap")):
        return real(name, *args, **kwargs)
    raise OSError("[WinError 126] 找不到指定的模块。")


ctypes._fw_real_windll = getattr(ctypes, "WinDLL", None)
ctypes.WinDLL = _fake_windll
'''


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'OK ' if ok else 'FAIL'}] {label}: {got!r}" + ("" if ok else f"  期望 {want!r}"))
    if not ok:
        FAILURES.append(label)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get_json(url: str, timeout: float = 4.0):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def get_text(url: str, timeout: float = 4.0) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="flowwatch-nonpcap-"))
    inject = work / "site"
    inject.mkdir()
    (inject / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")

    # 有构建产物就测 run.py（用户双击的那条路），否则退回 server.py（CI 里没有 dist）
    entry = ROOT / "run.py" if (ROOT / "web" / "dist" / "index.html").exists() else ROOT / "server.py"
    port = free_port()
    env = {**os.environ, "PYTHONPATH": str(inject), "PYTHONIOENCODING": "utf-8",
           "FLOWWATCH_DATA_DIR": str(work / "data")}
    out = (work / "out.log").open("w+", encoding="utf-8")
    err = (work / "err.log").open("w+", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, str(entry), "--port", str(port), "--no-browser", "--no-history"],
        cwd=str(ROOT), env=env, stdout=out, stderr=err,
    )
    print(f"[i] 启动 {entry.name}（端口 {port}，wpcap 被注入为不可加载）")
    health = None
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            if proc.poll() is not None:
                break
            try:
                _, health = get_json(f"http://127.0.0.1:{port}/api/health")
                break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                time.sleep(0.5)
        check("服务进程活着（没被采集层拖死）", proc.poll() is None, True)
        check("health 接口可用", health is not None, True)
        if health:
            check("status = degraded（不是假装 ok）", health.get("status"), "degraded")
            message = f"{health.get('error') or ''}"
            check("error 指明是 Npcap/wpcap", ("Npcap" in message or "wpcap" in message), True)
            check("device 为空但服务在（没数据≠没服务）", not health.get("device"), True)
        if entry.name == "run.py" and health:
            try:
                status, html = get_text(f"http://127.0.0.1:{port}/")
                check("前端页面照开（HTTP 200）", status, 200)
                check("返回的是真 HTML", "<div id=" in html, True)
            except (urllib.error.URLError, TimeoutError) as exc:
                check("前端页面照开（HTTP 200）", f"{type(exc).__name__}: {exc}", 200)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        out.close()
        err.close()

    if FAILURES:
        print("\n--- 子进程 stdout 末尾 ---")
        print("\n".join((work / "out.log").read_text(encoding="utf-8", errors="replace")
                        .splitlines()[-15:]))
        print("--- 子进程 stderr 末尾 ---")
        print("\n".join((work / "err.log").read_text(encoding="utf-8", errors="replace")
                        .splitlines()[-15:]))
        print(f"\n测试目录: {work}")

    if FAILURES:
        print(f"\n{len(FAILURES)} 项失败: {', '.join(FAILURES)}")
        return 1
    print("\n全部通过：无 Npcap 时服务照常起、页面照开、错误如实报")
    return 0


if __name__ == "__main__":
    sys.exit(main())
