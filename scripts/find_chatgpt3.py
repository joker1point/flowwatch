#!/usr/bin/env python3
"""find_chatgpt3 —— 识别 Edge 已安装的 4 个 PWA 分别是什么应用。

PWA 目录里通常有图标与缓存数据；应用名从 Edge 的 Web Applications 清单或
目录内可识别文件推断。若 ChatGPT 是 PWA 形态，进程名将是 msedge.exe
（--app-id 参数区分，代理客户端的 PROCESS-NAME 匹配不了命令行参数）→ 只能用域名规则。
"""
import os
from pathlib import Path

base = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "Web Applications"
if not base.is_dir():
    print("无 Web Applications 目录")
    raise SystemExit(0)

for app in sorted(base.iterdir()):
    if not app.name.startswith("_crx_"):
        continue
    app_id = app.name.replace("_crx_", "")
    print(f"== {app.name} ==")
    # 常见线索：icons 目录、manifest 缓存、Cookies 里的域名
    icons = list((app / "Icons").glob("*")) if (app / "Icons").is_dir() else []
    if icons:
        print(f"   icons: {[i.name for i in icons[:6]]}")
    # Edge 把 PWA 的 scope/URL 记在 Local Storage 或 manifest json
    hints: set[str] = set()
    for f in app.rglob("*.json"):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")[:2000]
        except Exception:
            continue
        for kw in ("chatgpt", "openai", "claude", "notion", "youtube", "figma",
                   "gmail", "keep", "notebooklm", "gemini", "perplexity", "copilot"):
            if kw in text.lower():
                hints.add(kw)
    if hints:
        print(f"   内容线索: {sorted(hints)}")
    # 目录大小 & 最近访问时间（近期在用的 PWA 会新鲜）
    try:
        st = app.stat()
        import datetime
        print(f"   mtime: {datetime.datetime.fromtimestamp(st.st_mtime):%Y-%m-%d %H:%M}")
    except Exception:
        pass
    print()
