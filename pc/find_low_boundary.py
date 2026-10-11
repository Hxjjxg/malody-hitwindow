# -*- coding: utf-8 -*-
"""找到 low 值变化的分界点。

支持两种日志格式:
  HIT  格式 (hit_log.txt)   : HIT {"n":1,"fn":...,"mask":30404924,"low":28,"bt":[...]}
  JUDGE格式 (judge_log.txt) : JUDGE down d=23ms mask=0x42 low=2

对 HIT 格式: 分界点用 n 定位, 列出前后 low/mask/fn/bt 差异。
对 JUDGE格式: 分界点用 d 定位, 列出前后 d/low 差异 (d 即用户要的 delta ms)。
"""
import json
import re
import sys
from pathlib import Path

BASE = Path(r"C:\Users\lenov\malody_re")
HIT_LOG = BASE / "hit_log.txt"
JUDGE_LOG = BASE / "judge_log.txt"

HIT_RE = re.compile(r"^HIT\s+(.*)$")
JUDGE_RE = re.compile(r"^JUDGE\s+(\S+)\s+d=(\S+?)ms\s+(?:time=\S+\s+)?mask=0x([0-9a-fA-F]+)\s+low=(\d+)")


def parse_hit(path):
    recs = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = HIT_RE.match(ln)
        if not m:
            continue
        try:
            r = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        recs.append({
            "n": r.get("n"), "fn": r.get("fn"), "mask": r.get("mask"),
            "low": r.get("low"), "bt": r.get("bt", []),
        })
    return recs


def parse_judge(path):
    recs = []
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = JUDGE_RE.match(ln)
        if not m:
            continue
        d_txt = m.group(2)
        d = None if d_txt == "?" else int(d_txt)
        recs.append({
            "name": m.group(1), "d": d,
            "mask": int(m.group(3), 16), "low": int(m.group(4)),
        })
    return recs


def find_boundaries(recs, key_fn):
    """返回 [(index, prev, cur)] 其中 index 是 low 开始变化的记录下标。"""
    bounds = []
    prev = None
    for i, r in enumerate(recs):
        low = r["low"]
        if prev is not None and low != prev["low"]:
            bounds.append((i, prev, r))
        prev = r
    return bounds


def fmt_bt(bt):
    return " -> ".join(bt[:6]) if bt else "-"


def report_hit(recs):
    print(f"[hit_log] 共 {len(recs)} 条 HIT 记录\n")
    # 连续段 (run) 概览
    runs = []
    cur = [recs[0]]
    for r in recs[1:]:
        if r["low"] == cur[-1]["low"]:
            cur.append(r)
        else:
            runs.append(cur)
            cur = [r]
    runs.append(cur)
    print("low 连续段:  (每段: n 范围 / low / mask / fn)")
    for run in runs:
        first, last = run[0], run[-1]
        label = f"{first['n']}-{last['n']}" if first['n'] != last['n'] else str(first['n'])
        print(f"  n={label:>9}  low={first['low']:<4} mask=0x{first['mask']:08X}  fn={first['fn']}")
    print()

    bounds = find_boundaries(recs, lambda r: r["low"])
    if not bounds:
        print("== 无分界点: low 全程未变化 ==")
        return
    print(f"== 分界点 {len(bounds)} 处 (low 变化) ==")
    for i, prev, cur in bounds:
        print(f"\n  >>> 分界 @ 记录#{i} (n={cur['n']})")
        print(f"      之前: low={prev['low']:<3} mask=0x{prev['mask']:08X} fn={prev['fn']}")
        print(f"                 bt={fmt_bt(prev['bt'])}")
        print(f"      之后: low={cur['low']:<3} mask=0x{cur['mask']:08X} fn={cur['fn']}")
        print(f"                 bt={fmt_bt(cur['bt'])}")
    print("\n注意: HIT 格式不含 d (delta ms)。mask 高位非单调时间(0x1CFF1/0x1CFF6 交替)，"
          "需 judge 钩子(frida_read_judge.py)才能拿到 d。")


def report_judge(recs):
    print(f"[judge_log] 共 {len(recs)} 条 JUDGE 记录\n")
    if not recs:
        print("== 无 JUDGE 记录 (钩子只打印了 hooked 行, 会话内没有实际判定事件) ==")
        return
    for r in recs:
        d = r["d"] if r["d"] is not None else "?"
        print(f"  {r['name']:<5} d={d:>5}ms  mask=0x{r['mask']:02X}  low={r['low']}")
    print()
    bounds = find_boundaries(recs, lambda r: r["low"])
    if not bounds:
        print("== 无分界点: low 全程未变化 ==")
        return
    print(f"== 分界点 {len(bounds)} 处 (low 变化) ==")
    for i, prev, cur in bounds:
        pd = prev["d"] if prev["d"] is not None else "?"
        cd = cur["d"] if cur["d"] is not None else "?"
        print(f"  >>> 分界 @ #{i}: 之前 d={pd}ms low={prev['low']}  ->  之后 d={cd}ms low={cur['low']}")


def main():
    hit = parse_hit(HIT_LOG)
    judge = parse_judge(JUDGE_LOG)
    report_hit(hit)
    print("-" * 70)
    report_judge(judge)
    return 0


if __name__ == "__main__":
    sys.exit(main())
