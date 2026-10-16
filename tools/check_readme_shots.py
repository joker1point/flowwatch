#!/usr/bin/env python3
"""README 素材规范校验（纯标准库，Windows / macOS / Linux 通用）。

用法：
    python check_readme_shots.py <项目路径> [<项目路径> ...]
    python check_readme_shots.py --scan <父目录>        # 扫描其下所有含 README 的一级子目录
    python check_readme_shots.py <项目路径> --json      # 机器可读输出

检查项（依据《README 素材规范》）：
  1. README 存在
  2. 功能点数 N（自动估计）→ 规范要求的最少素材数
  3. 内嵌素材数（本地图片/GIF；自动排除 badge 与赞助商/logo 墙）
  4. 首屏主图：第一张功能图是否在文档前部（≤12% 或前 12 行）
  5. 破损引用：README 引用的本地文件是否存在
  6. 体积：PNG > 1.5 MB、GIF > 5 MB（硬上限 10 MB）
  7. 形式建议：正文出现交互/时序关键词但没有任何 GIF → 提醒
  8. 动图是否只被链接未内嵌（README 只链接到 `docs/*-demo.md` 之类的子文档）
退出码：0 = 全部达标；1 = 存在不达标或错误。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BADGE_HINT = ("shields.io", "badgen", "/badge", "badge.svg", "codecov", "coveralls",
              "github/actions/workflows", "/actions/workflows/", "travis-ci", "circleci",
              "badge.fury", "repology", "img.shields")
NOISE_HINT = ("sponsor", "backer", "patreon", "opencollective", "contributor", "avatar",
              "/logo", "logo.", "icons/", "/icon-", "brand", "partner")

# 交互 / 时序 关键词：出现这些应当有 GIF（或 mp4）
MOTION_HINT = ("拖拽", "拖放", "向导", "进度", "实时", "多步", "右键", "翻页", "动画",
               "drag", "wizard", "progress", "live", "real-time", "context menu")

PNG_LIMIT = 1.5 * 1024 * 1024
GIF_LIMIT = 5 * 1024 * 1024
GIF_HARD = 10 * 1024 * 1024


def is_badge(u: str) -> bool:
    low = u.lower()
    return any(h in low for h in BADGE_HINT)


def is_noise(u: str) -> bool:
    low = u.lower()
    return any(h in low for h in NOISE_HINT)


def extract_refs(text: str) -> list[tuple[str, str]]:
    """返回 [(url, alt_or_empty)]，含 markdown 与 html 两种写法。"""
    md = [(u, a) for a, u in re.findall(r"!\[([^\]]*)\]\(([^)\s]+)", text)]
    html = [(u, "") for u in re.findall(r'<img[^>]+src="([^"\']+)"', text)]
    vids = [(u, "video") for u in re.findall(r'<video[^>]+src="([^"\']+)"', text)]
    return md + html + vids


def count_features(text: str) -> tuple[int | None, str]:
    """估计面向用户的功能点数。

    优先级：显式声明 > 功能表（##/### 级）> 列表型章节。
    显式声明写法（推荐新项目直接加，省得靠猜）：
        <!-- README-SHOTS: N=5 -->
    """
    m = re.search(r"README-SHOTS\s*:\s*N\s*=\s*(\d+)", text)
    if m:
        return int(m.group(1)), "显式声明 README-SHOTS"

    head_kw = (r"功能|能力|特性|亮点|能做什么|解决的问题|它替你|这是什么|"
               r"Features?|Capabilities|Highlights|What it does")
    for lvl in (r"##", r"###"):
        m = re.search(rf"{lvl}\s*[^\n]*(?:{head_kw})[^\n]*\n(.*?)(?=\n{lvl}\s|\Z)",
                      text, re.S | re.I)
        if not m:
            continue
        rows = [ln for ln in m.group(1).splitlines() if ln.strip().startswith("|")]
        n = max(0, len(rows) - 2)                      # 去表头与分隔行
        if n:
            return n, "功能表"
        n = len(re.findall(r"^\s*(?:\d+[.、)]|[-*+])\s+\S", m.group(1), re.M))
        if n:
            return n, "章节列表"

    # 3) 兜底：正文自述「它替你干的四件事」「3 个能力」这类写法。
    #    只认 ≥3 —— 否则「一件事」这种口语表述会误判（实测踩过）。
    cn = {"一": 1, "两": 2, "二": 2, "三": 3, "四": 4, "五": 5,
          "六": 6, "七": 7, "八": 8, "九": 9, "十": 10}
    m = re.search(r"((?:\d+)|[一二两三四五六七八九十]+)\s*(?:件|个|项)\s*(?:事|功能|能力|特性)",
                  text)
    if m:
        raw = m.group(1)
        n = int(raw) if raw.isdigit() else cn.get(raw, 0)
        if n >= 3:
            return n, "正文自述"
    return None, "未识别"


def required_count(n: int | None) -> int | None:
    if n is None:
        return None
    if n <= 3:
        return 1
    if n <= 6:
        return 2
    if n <= 10:
        return 3
    return 4 + (n - 11) // 5


def size_of(target: Path) -> int | None:
    try:
        return target.stat().st_size
    except OSError:
        return None


def check_project(root: Path) -> dict:
    res: dict = {"project": root.name, "path": str(root), "issues": [], "warns": [], "notes": []}
    readme = root / "README.md"
    if not readme.exists():
        res["issues"].append("README.md 不存在")
        return res
    text = readme.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # 素材
    refs = extract_refs(text)
    local = [(u, a) for u, a in refs
             if not u.startswith(("http://", "https://")) and not is_badge(u) and not is_noise(u)]
    gifs = [(u, a) for u, a in local if u.lower().split("?")[0].endswith(".gif")]
    pngs = [(u, a) for u, a in local if u.lower().split("?")[0].endswith((".png", ".jpg", ".jpeg", ".webp"))]
    vids = [(u, a) for u, a in refs if u.lower().endswith(".mp4") or a == "video"]
    res["counts"] = {"local": len(local), "png": len(pngs), "gif": len(gifs), "mp4": len(vids)}

    # 功能点与要求
    n, how = count_features(text)
    need = required_count(n)
    res["features"] = {"n": n, "how": how, "required": need}
    if need is not None:
        if len(local) < need:
            res["issues"].append(f"素材不足：功能点 {n}（{how}）→ 规范要求 ≥{need} 张，实测 {len(local)} 张")
        else:
            res["notes"].append(f"素材数量达标：{len(local)}/{need}")
    else:
        res["warns"].append("未能自动识别功能点——建议在 README 顶部加一行显式声明："
                            "<!-- README-SHOTS: N=<功能数> -->，或人工核对最少素材数")

    # 首屏主图
    pos = []
    for u, _ in local:
        i = text.find(u)
        if i >= 0:
            pos.append(text[:i].count("\n") + 1)
    first = min(pos) if pos else None
    res["hero_line"] = first
    if local:
        limit = max(12.0, len(lines) * 0.12)
        if first is not None and (first > limit or first > 80):
            res["warns"].append(
                f"首屏主图偏后（第 {first} 行，建议 ≤{int(min(limit, 80))} 行）"
                "——规范要求标题+简介后立刻出现")
        else:
            res["notes"].append(f"首屏主图位置合格（第 {first} 行）")
    else:
        res["issues"].append("README 里没有任何本地素材图")

    # 破损引用 + 体积
    for u, _ in local:
        f = root / u
        if not f.exists():
            res["issues"].append(f"引用的文件不存在：{u}")
            continue
        sz = size_of(f)
        if sz is None:
            continue
        if u.lower().endswith(".gif"):
            if sz > GIF_HARD:
                res["issues"].append(f"GIF 超过硬上限：{u}（{sz/1e6:.1f} MB > 10 MB）")
            elif sz > GIF_LIMIT:
                res["warns"].append(f"GIF 偏大：{u}（{sz/1e6:.1f} MB，建议 ≤5 MB）")
        elif sz > PNG_LIMIT:
            res["warns"].append(f"图片偏大：{u}（{sz/1e6:.1f} MB，建议 ≤1.5 MB）")

    # 形式建议：有交互/时序关键词但没有 GIF
    low = text.lower()
    hits = [k for k in MOTION_HINT if (k in text) or (k.lower() in low)]
    if hits and not gifs and not vids:
        res["warns"].append("出现交互/时序关键词（" + "、".join(hits[:4]) +
                            "…）但没有 GIF/视频——若确有这类功能，规范要求上动图")

    # 动图是否只被链接未内嵌
    linked_docs = re.findall(r"\]\(([^)\s]+\.md)\)", text)
    for d in dict.fromkeys(linked_docs):
        p = root / d
        if p.exists() and p != readme:
            sub = p.read_text(encoding="utf-8", errors="replace")
            sub_refs = [u for u, a in extract_refs(sub)
                        if not u.startswith("http") and not is_badge(u) and not is_noise(u)]
            if sub_refs:
                res["warns"].append(f"素材集中在子文档 {d}（{len(sub_refs)} 张）——建议主 README 内嵌 1–2 张关键动图，别让读者多跳一次")

    res["ok"] = not res["issues"]
    return res


def render(res: dict) -> None:
    tag = "PASS" if res.get("ok") else "FAIL"
    print(f"== {res['project']}  [{tag}]  {res['path']}")
    c = res.get("counts")
    if c:
        print(f"   素材：{c['local']} 张（PNG {c['png']} / GIF {c['gif']} / mp4 {c['mp4']}）")
    f = res.get("features")
    if f:
        need = f["required"] if f["required"] is not None else "?"
        print(f"   功能点：{f['n']}（{f['how']}）→ 需 ≥{need} 张")
    for s in res.get("notes", []):
        print(f"   [OK]   {s}")
    for s in res.get("warns", []):
        print(f"   [WARN] {s}")
    for s in res.get("issues", []):
        print(f"   [FAIL] {s}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="README 素材规范校验")
    ap.add_argument("paths", nargs="*", help="项目路径（可多个）")
    ap.add_argument("--scan", help="扫描该目录下所有含 README.md 的一级子目录")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    roots: list[Path] = []
    if args.scan:
        base = Path(args.scan)
        roots += [d for d in sorted(base.iterdir()) if (d / "README.md").exists()]
    roots += [Path(p) for p in args.paths]
    if not roots:
        ap.print_help()
        return 1

    results = [check_project(r) for r in roots if r.is_dir()]
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for r in results:
            render(r)
        bad = [r["project"] for r in results if not r.get("ok")]
        total = len(results)
        print(f"汇总：{total} 个项目，达标 {total - len(bad)}，不达标 {len(bad)}"
              + (f"（{', '.join(bad)}）" if bad else ""))
    return 0 if all(r.get("ok") for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
