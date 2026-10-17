#!/usr/bin/env python3
"""find_chatgpt2 —— 深挖：商店版 Packages / Edge PWA / 已装 UWP 应用。"""
import os
from pathlib import Path

print("== 1. UWP/商店应用清单（OpenAI 相关） ==")
try:
    import subprocess
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-AppxPackage | Where-Object { $_.Name -match 'openai|chatgpt' } | "
                        "Select-Object Name, PackageFullName, InstallLocation | Format-List"],
                       capture_output=True, text=True, timeout=60)
    print(r.stdout.strip() or "  （无 OpenAI 商店应用）")
except Exception as e:
    print("  查询失败:", e)

print("\n== 2. Packages 目录（商店应用可执行文件） ==")
pkgs = Path(os.environ.get("LOCALAPPDATA", "")) / "Packages"
if pkgs.is_dir():
    for d in sorted(pkgs.iterdir()):
        if "openai" in d.name.lower() or "chatgpt" in d.name.lower():
            print(f"  {d.name}")
            for exe in sorted(d.rglob("*.exe"))[:5]:
                print(f"    exe: {exe}")
else:
    print("  （无 Packages 目录）")

print("\n== 3. Edge PWA 应用（装在 LocalCache 的网站应用） ==")
edge_base = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data"
if edge_base.is_dir():
    for prof in sorted(edge_base.glob("*")):
        wapps = prof / "Web Applications"
        if wapps.is_dir():
            for app in sorted(wapps.iterdir()):
                print(f"  {prof.name}/{app.name}")
else:
    print("  （无 Edge 用户数据目录）")
