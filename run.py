#!/usr/bin/env python3
"""flowwatch 开箱即用启动器：**单端口**（界面 + API 同源）、自动装依赖、自动开浏览器。

它适合"只想看数据"的用户：不需要 npm、不需要两个终端、不需要记参数。
开发（改前端源码 / HMR）仍走 README 里的 8788 + 5273 两端口流程。

用法：
    python run.py                         # → http://127.0.0.1:8791/
    python run.py --port 8080 --dev WLAN   # 指定端口 / 抓包设备
    python run.py --no-browser            # 不自动开浏览器（服务器 / 远程桌面）
    python run.py --no-history            # 纯实时，不落历史库

与 `server.py` 的关系：**同一份后端代码**。本文件只做三件事 ——
  1. 在 uvicorn 起服务之前把 `web/dist` 挂到同一个 FastAPI 应用上（同源、单端口）；
  2. 把"没有配置模型"的默认档设成 mock（不联网、仍真跑工具），避免第一次打开就是一句
     "未配置模型"的报错；
  3. 打开浏览器 + 打印需要的驱动提示。
不复制、不改写任何业务代码 —— 这是"演示包与源码不漂移"的同一条原则（见 _deploy 包装层）。
"""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIST = HERE / "web" / "dist"
REQUIREMENTS = HERE / "requirements.txt"


def _ensure_dependencies(no_install: bool) -> bool:
    """依赖缺失时自动 `pip install -r requirements.txt`（可用 --no-install 关掉）。

    开源用户的第一次失败几乎都发生在这一步（装了 Python 但没装 fastapi / psutil），
    所以默认自动补齐，并把"我在装什么"如实打印出来。
    """
    missing: list[str] = []
    for module, package in (("psutil", "psutil"), ("fastapi", "fastapi"), ("uvicorn", "uvicorn")):
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if not missing:
        return True
    print(f"[flowwatch] 缺少依赖: {', '.join(missing)}", flush=True)
    if no_install:
        print("[flowwatch] 已指定 --no-install：请手动执行  pip install -r requirements.txt", flush=True)
        return False
    if not REQUIREMENTS.exists():
        print(f"[flowwatch] 找不到 {REQUIREMENTS}，请手动执行  pip install psutil fastapi uvicorn", flush=True)
        return False
    print(f"[flowwatch] 正在安装依赖（{sys.executable} -m pip install -r requirements.txt）…", flush=True)
    import subprocess

    code = subprocess.call([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)])
    return code == 0


def _check_dist() -> bool:
    index = DIST / "index.html"
    if index.exists():
        return True
    print("[flowwatch] 没有找到前端构建产物: web/dist/index.html", flush=True)
    print("[flowwatch] 两条路：", flush=True)
    print("  1) 用官方一键包（Release 里的 flowwatch-*-windows.zip，自带构建好的界面）；", flush=True)
    print("  2) 自己构建：cd web && npm install && VITE_API_BASE=/ npm run build", flush=True)
    return False


def _warn_if_dev_build() -> None:
    """workspace 里常见状态：`web/dist` 是**两端口（开发）构建**，页面会去请求 127.0.0.1:8788。
    这时单端口模式下界面能打开、但数据是空的 —— 如实提示，而不是让人对着一个空壳猜原因。"""
    try:
        for js in (DIST / "assets").glob("*.js"):
            if b"127.0.0.1:8788" in js.read_bytes():
                print("[flowwatch] 注意：这份 web/dist 是开发模式构建（前端会请求 127.0.0.1:8788）。", flush=True)
                print("           想单端口用：cd web && VITE_API_BASE=/ npm run build，或直接用官方一键包。", flush=True)
                return
    except OSError:
        pass


def _check_npcap() -> None:
    """抓包依赖 wpcap.dll（Npcap 或兼容的 WinPcap）。缺了不是致命错 —— 界面照开，
    只是没有数据；所以这里只提示，不退出。"""
    if sys.platform != "win32":
        print("[flowwatch] 注意：抓包层仅支持 Windows（界面仍可打开，但没有数据）。", flush=True)
        return
    import ctypes

    try:
        ctypes.WinDLL("wpcap.dll")
        return
    except OSError:
        pass
    print("[flowwatch] 未检测到 wpcap.dll —— 抓包需要先装 Npcap（驱动级依赖，需单独安装）：", flush=True)
    print("           https://npcap.com/#download  （安装向导里无需勾选 WinPcap 兼容模式）", flush=True)
    print("           装完后重启本程序即可；在此之前界面能打开，但不会有流量数据。", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="flowwatch 一键启动（单端口：界面 + API）")
    parser.add_argument("--port", type=int, default=8791, help="服务端口（默认 8791）")
    parser.add_argument("--dev", help="抓包设备名/描述片段（默认自动挑最忙的）")
    parser.add_argument("--db", default=None, help="历史库路径（默认与本项目同目录的 history.db）")
    parser.add_argument("--retention-days", type=float, default=None, help="时间桶保留天数（默认 30）")
    parser.add_argument("--no-history", action="store_true", help="不落历史（纯实时模式）")
    parser.add_argument("--etw", action="store_true", help="ETW 补全归因（需管理员；非提权自动降级）")
    parser.add_argument("--etw-udp", action="store_true", help="配合 --etw：额外消费 UDP 事件（opt-in）")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--no-install", action="store_true", help="缺依赖时不自动 pip install")
    args = parser.parse_args(argv)

    if not _ensure_dependencies(args.no_install):
        return 1
    if not _check_dist():
        return 2
    _warn_if_dev_build()
    _check_npcap()

    sys.path.insert(0, str(HERE))
    import server as srv  # noqa: E402  —— 与 server.py 完全同一份后端

    # 启动参数：与 server.py 的 CLI 语义一致，只是默认值面向"第一次打开的人"
    if args.dev:
        srv.capturer.device = args.dev
    srv.capturer.use_etw = args.etw
    srv.capturer.use_etw_udp = args.etw_udp
    if args.db:
        srv.store.path = Path(args.db)
    if args.retention_days is not None:
        srv.store.retention_days = args.retention_days
    if args.no_history:
        srv.store.enabled = False

    # 没配模型时默认 mock：链路（工具调用 + 记忆）照常可演示，输出明确标注 mock。
    # 已经用「模型设置」存过配置（assistant_config.json）或设了环境变量则不动它。
    import assistant  # noqa: E402

    if not assistant.load_config().configured and not os.environ.get("FLOWWATCH_ASSISTANT_PROVIDER"):
        os.environ["FLOWWATCH_ASSISTANT_PROVIDER"] = "mock"
        os.environ.setdefault("FLOWWATCH_ASSISTANT_MODEL", "mock")
        print("[flowwatch] 流量助手未配置模型 → 先用 mock 档（不联网，仍真跑工具）；"
              "面板右上「模型设置」可随时换成真模型。", flush=True)

    # 单端口：路由先匹配（/api/*），其余落到静态挂载 —— 与 _deploy 包装层同一顺序
    from fastapi.staticfiles import StaticFiles

    srv.app.mount("/", StaticFiles(directory=str(DIST), html=True), name="ui")

    url = f"http://127.0.0.1:{args.port}/"
    print(f"[flowwatch] 界面与 API 都在 {url}（Ctrl+C 退出）", flush=True)
    if not args.no_browser:
        import threading

        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    import uvicorn

    try:
        uvicorn.run(srv.app, host="127.0.0.1", port=args.port, log_level="info")
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
