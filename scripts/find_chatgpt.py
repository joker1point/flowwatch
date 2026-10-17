#!/usr/bin/env python3
"""find_chatgpt —— 推断 ChatGPT 桌面版的可执行文件名（分流规则要用）。

查两条路：常见安装目录、开始菜单/桌面快捷方式(.lnk)。
桌面 App 常是多进程（主/渲染/GPU），PROCESS-NAME 匹配的是 exe 名——
打开应用后由 who_uses_proxy.py 实测确认最终名单。
"""
import os
import sys
from pathlib import Path

CANDIDATE_DIRS = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "ChatGPT",
    Path(os.environ.get("LOCALAPPDATA", "")) / "ChatGPT",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "chatgpt",
    Path("C:/Program Files/ChatGPT"),
    Path("C:/Program Files (x86)/ChatGPT"),
]
START_MENU = [
    Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs",
    Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs"),
]
DESKTOP = [
    Path.home() / "Desktop",
    Path.home() / "OneDrive" / "Desktop",
]


def scan_lnk(paths: list[Path]) -> list[str]:
    """用 WScript.Shell 读 .lnk 的 TargetPath（无需 python 包）。"""
    found: list[str] = []
    try:
        import win32com.client  # type: ignore
        shell = win32com.client.Dispatch("WScript.Shell")
    except Exception:
        shell = None
    for base in paths:
        if not base.is_dir():
            continue
        for lnk in base.rglob("*.lnk"):
            name = lnk.stem.lower()
            if "chatgpt" not in name and "openai" not in name:
                continue
            target = ""
            if shell is not None:
                try:
                    target = shell.CreateShortCut(str(lnk)).TargetPath
                except Exception:
                    target = ""
            if not target:
                target = f"（未能解析目标，lnk={lnk}）"
            found.append(f"{lnk.stem} → {target}")
    return found


if __name__ == "__main__":
    print("== 安装目录扫描 ==")
    exes: list[str] = []
    for d in CANDIDATE_DIRS:
        if not d.is_dir():
            continue
        print(f"  {d}")
        for f in sorted(d.rglob("*.exe"))[:10]:
            print(f"    exe: {f.name}")
            exes.append(f.name)
    if not exes:
        print("  （常见目录未找到）")
    print("\n== 快捷方式 ==")
    links = scan_lnk(START_MENU + DESKTOP)
    print("\n".join(f"  {l}" for l in links) if links else "  （未找到 ChatGPT 快捷方式）")
    print("\nPROCESS-NAME 候选进程名：", sorted(set(exes)) or "未知（打开应用后由 who_uses_proxy.py 实测）")
