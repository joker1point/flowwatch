# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包定义：把 flowwatch 打成一个**双击即用**的 exe（onedir）。

用法（在仓库根目录）：
    cd web && VITE_API_BASE=/ npm run build && cd ..      # 先构建同源前端
    python -m PyInstaller packaging/flowwatch.spec --noconfirm
产物：
    dist/flowwatch/flowwatch.exe     ← 双击运行；界面与 API 同源在 http://127.0.0.1:8791/
    同目录的 _internal/ 必须跟着一起分发

为什么用 onedir 而不是 --onefile：
  · 启动快（onefile 每次运行都要把几十 MB 解压到临时目录再启动）；
  · 杀软误报更少 —— onefile 的自解压引导器在"管家类 + Defender"双杀软环境下更容易被拦。

两个**必须**知道的边界：
  · Npcap 是驱动级依赖，**不进包**（系统级安装一次）—— 没装时界面能开、没有数据；
  · 运行期数据（history.db / assistant_memory.db / notes/ / assistant_config.json）落在
    **exe 所在目录**（见 datadir.py）—— 代码资源在只读的 _MEIPASS 里，写在那里会被清掉。

本地调试可用环境变量 FLOWWATCH_DIST 指定别的 dist 目录（例如复用一键包里的同源构建）。

**构建环境要干净**：请在只装了 `requirements.txt + pyinstaller` 的 venv 里构建。
在 conda 基环境里构建会把无关的包一起带进去 —— 同一个 spec 实测 **207 MB（基环境）vs 33 MB（干净 venv）**，
多出来的正是 jieba / sphinx / babel / jedi / PyQt5 这类谁都没 import 的东西。
"""

import os

PROJECT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 - SPECPATH 由 PyInstaller 注入
DIST = os.environ.get("FLOWWATCH_DIST") or os.path.join(PROJECT, "web", "dist")

a = Analysis(
    [os.path.join(PROJECT, "run.py")],
    pathex=[PROJECT],
    binaries=[],
    datas=[(DIST, "web/dist")],
    hiddenimports=[
        # uvicorn 的 loop / protocol 是按名字动态加载的：不显式列出来会出现"能起服务、立刻报错"
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "numpy", "pandas", "matplotlib", "PIL"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="flowwatch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX 压缩会显著抬高杀软误报率，明确关掉
    console=True,              # 保留控制台：日志与"缺 Npcap"的提示都在这里
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="flowwatch",
)
