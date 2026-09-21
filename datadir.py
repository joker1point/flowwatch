#!/usr/bin/env python3
"""运行期数据目录（history.db / assistant_memory.db / notes/ / .env / _run）的统一出处。

为什么单独一个模块：打包成 exe（PyInstaller）之后，`__file__` 指向**只读的临时解包目录**
（`sys._MEIPASS`）—— 在那里写 SQLite 会随进程退出被清掉，用户看到的现象是
"历史与助手记忆每次重启都清空"。所以"可写数据"必须和"代码资源"分开定位：

    · 源码运行   → 项目目录（与原行为完全一致，不改变任何现有路径）
    · 打包成 exe → **exe 所在目录**（与 exe 并排：用户看得见、能备份、能删）
    · 显式覆盖   → 环境变量 `FLOWWATCH_DATA_DIR`

打包后代码资源（`web/dist`、集成插件）仍在 `_MEIPASS` 里，那是只读的，由 spec 的 datas 带进去。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """可写的运行期数据目录。"""
    override = os.environ.get("FLOWWATCH_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if getattr(sys, "frozen", False):        # PyInstaller 运行时会设 sys.frozen = True
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def data_path(name: str) -> Path:
    """数据目录下的某个文件 / 子目录（不创建，调用方按需创建）。"""
    return data_dir() / name
