#!/usr/bin/env python3
"""find_chatgpt4 —— Edge 历史里 ChatGPT 相关域名的访问统计（只出域名计数，不读明细）。

判据：如果 Edge 历史里有大量 chatgpt.com / openai.com 访问，用户的「桌面 App」
大概率是 Edge PWA（或网页标签）——PWA 的进程名是 msedge.exe，
代理客户端的 PROCESS-NAME 匹配不了 --app-id 参数 → 必须用域名规则。
"""
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

HIST = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "History"
KEYWORDS = ("chatgpt.com", "openai.com", "chat.openai.com", "oaistatic.com", "oaiusercontent.com")

if not HIST.exists():
    print(f"无 Edge 历史库：{HIST}")
    raise SystemExit(0)

# Edge 在运行时会锁库：复制到临时文件再只读打开
tmp = Path(tempfile.gettempdir()) / "edge_hist_probe.db"
shutil.copy2(HIST, tmp)
conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
print("== Edge 历史：OpenAI 相关域名访问次数（近 90 天） ==")
total = 0
for kw in KEYWORDS:
    row = conn.execute(
        "SELECT COUNT(*), MAX(last_visit_time) FROM urls WHERE url LIKE ?",
        (f"%{kw}%",),
    ).fetchone()
    if row[0]:
        total += row[0]
        print(f"  {kw:22s} {row[0]:5d} 次")
print(f"\n合计 {total} 次访问")
if total > 0:
    print("→ 判据成立：ChatGPT 走 Edge（PWA 或标签页）。分流应用域名规则，不要用 PROCESS-NAME。")
else:
    print("→ Edge 无 OpenAI 访问记录。「桌面 App」可能真是独立应用（本机未找到安装），打开后实测进程名。")
conn.close()
tmp.unlink(missing_ok=True)
