"""开机自启开关（Windows 注册表 Run 键，HKCU —— 无需管理员）。

为什么选这个方案：计划任务更强但要 schtasks（可能触发 UAC），启动文件夹要造 .lnk；
Run 键一行写入、一行删除，用户级生效，是最轻的可逆做法。

两条刻意的诚实：
  · 非 Windows 平台直接回 "不支持"，不假装成功；
  · 写进去的命令 = 「当前解释器 + server.py + 当前启动参数」——
    即"把现在这条命令记下来"，而不是猜一个推荐命令（设备、端口、保留天数都以现状为准）。
"""

import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger("flowwatch.autostart")

VALUE_NAME = "flowwatch"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def current_command() -> str:
    """自启命令：复制"现在这条命令"，参数原样带走（含 --dev / --retention-days 等）。"""
    parts = [f'"{sys.executable}"', f'"{Path(__file__).with_name("server.py")}"']
    for arg in sys.argv[1:]:
        parts.append(f'"{arg}"' if " " in arg else arg)
    return " ".join(parts)


def _read_value() -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
            return str(value)
    except OSError:
        return None


def status() -> dict[str, Any]:
    if sys.platform != "win32":
        return {"supported": False, "enabled": False, "command": "", "detail": "仅 Windows 支持"}
    saved = _read_value()
    return {
        "supported": True,
        "enabled": saved is not None,
        "command": saved or current_command(),   # 未启用时给出"启用后会写入的命令"
        "detail": "HKCU Run 键（无需管理员，随时可关）",
    }


def set_enabled(enabled: bool) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"supported": False, "enabled": False, "command": "", "detail": "仅 Windows 支持"}
    import winreg

    command = current_command()
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
            logger.info("已开启开机自启: %s", command)
        else:
            try:
                winreg.DeleteValue(key, VALUE_NAME)
                logger.info("已关闭开机自启")
            except FileNotFoundError:
                pass
    result = status()
    if enabled:
        result["command"] = command
    return result
