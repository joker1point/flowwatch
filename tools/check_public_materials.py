#!/usr/bin/env python3
"""对外材料红线扫描（2026-10-16）：代理软件品牌名 + 敏感凭据。

依据：工作区规则「对外材料不出现 FLCLASH」—— 代理软件名不进公开材料 / 公开仓
（README、UI 文案、源码注释、测试夹具都算），提及时泛化为「某代理进程」。

用法：
    python check_public_materials.py [<仓库根>]      # 默认当前目录

扫描范围：git 跟踪的文件（`git ls-files`）；非 git 仓库时回退为遍历（跳过构建目录与二进制）。
豁免：行内含 `public-materials: ignore` 的行跳过（请写清理由再豁免）。
输出：GitHub Actions 注解（::error / ::warning）+ 逐条明细。
退出码：0 = 干净；1 = 命中硬红线（品牌词或高置信凭据）。
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# 品牌词（硬红线）：不区分大小写的子串匹配
BRAND_HARD = ["flclash", "mihomo", "clash"]

# 代理 / 机场相关（只警告）——出现在说明性文字里可能是有意保留
BRAND_WARN = ["hysteria", "v2ray", "xray", "sing-box", "trojan", "vmess", "shadowsocks", "机场"]

# 高置信凭据（硬红线）
SECRET_HARD = [
    r"sk-[A-Za-z0-9_-]{20,}",
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
]

# 低置信（只警告）：明文口令 / 密钥赋值
SECRET_WARN = [
    r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
]

SKIP_DIRS = {".git", "node_modules", "target", ".venv", "venv", "dist", "build",
             "__pycache__", ".next", ".mypy_cache", ".pytest_cache",
             # vendor / 生成物目录（2026-10-16 补：techlog 的 .yarn/releases 里
             # 压缩后的 yarn 源码含 "clash" 子串 → 误报。vendor 文件不由我们维护）
             ".yarn", ".cache", "vendor", "third_party"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".exe",
            ".dll", ".so", ".dylib", ".mp3", ".mp4", ".wav", ".woff", ".woff2", ".ttf",
            ".rlib", ".rmeta", ".o", ".a", ".db", ".sqlite", ".pyc", ".bin", ".7z", ".tar", ".gz"}
# 压缩/产物流（同上：vendored，不按源码扫）
SKIP_NAME_TAIL = (".min.js", ".min.css", ".min.mjs", ".map")

IGNORE_MARK = "public-materials: ignore"
SELF_NAME = "check_public_materials.py"


def tracked_files(root: Path) -> list[Path]:
    """git 跟踪的文件；失败则回退遍历。"""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                             capture_output=True, check=True).stdout
        files = [root / p for p in out.decode("utf-8", "replace").split("\0") if p]
        if files:
            return files
    except Exception:
        pass
    files = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        files.append(p)
    return files


def read_text(p: Path) -> str | None:
    if p.suffix.lower() in SKIP_EXT:
        return None
    try:
        raw = p.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def scan(root: Path) -> int:
    hard_hits: list[str] = []
    warn_hits: list[str] = []
    hard_pat = [(t, re.compile(re.escape(t), re.I)) for t in BRAND_HARD]
    warn_pat = [(t, re.compile(re.escape(t), re.I)) for t in BRAND_WARN]
    sec_hard = [re.compile(p) for p in SECRET_HARD]
    sec_warn = [re.compile(p) for p in SECRET_WARN]

    n_files = 0
    for p in sorted(tracked_files(root)):
        if p.name == SELF_NAME or p.name.endswith(SKIP_NAME_TAIL):
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        text = read_text(p)
        if text is None:
            continue
        n_files += 1
        rel = p.relative_to(root).as_posix()
        for i, line in enumerate(text.splitlines(), 1):
            if IGNORE_MARK in line:
                continue
            for term, rx in hard_pat:
                if rx.search(line):
                    hard_hits.append(f"::error file={rel},line={i}::品牌词「{term}」不得进入公开材料"
                                     f"（泛化为「某代理进程」）：{line.strip()[:120]}")
            for term, rx in warn_pat:
                if rx.search(line):
                    warn_hits.append(f"::warning file={rel},line={i}::疑似代理相关词「{term}」"
                                     f"（如非有意保留，建议泛化）：{line.strip()[:120]}")
            for rx in sec_hard:
                if rx.search(line):
                    hard_hits.append(f"::error file={rel},line={i}::疑似凭据泄漏"
                                     f"（{rx.pattern[:28]}）：{line.strip()[:80]}")
            for rx in sec_warn:
                m = rx.search(line)
                if m:
                    warn_hits.append(f"::warning file={rel},line={i}::疑似明文口令/密钥赋值：{m.group(0)[:80]}")

    print(f"[check_public_materials] 扫描 {n_files} 个文本文件（git 跟踪范围）")
    for h in hard_hits:
        print(h)
    for w in warn_hits:
        print(w)
    print(f"[check_public_materials] 硬红线 {len(hard_hits)} 处 / 警告 {len(warn_hits)} 处")
    if hard_hits:
        print("[check_public_materials] 结论：FAIL —— 修掉硬红线后再提交")
        return 1
    print("[check_public_materials] 结论：PASS" + ("（警告请人工过目）" if warn_hits else ""))
    return 0


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    if not root.is_dir():
        print(f"路径不存在：{root}")
        return 2
    return scan(root)


if __name__ == "__main__":
    sys.exit(main())
