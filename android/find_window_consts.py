# -*- coding: utf-8 -*-
"""在已解码的 arm64 指令缓存里, 按"窗口常量立即数"找设置判定窗口的函数。

背景: 手机实测判定窗口槽位 = 45/85/130/170 (base 另加)。
      上一轮按桌面常量 36/76/110/160 搜数据段全零命中 —— 因为这些小立即数
      在 arm64 上是编进 `mov w?, #imm` 指令的, 不在 .data 里。

用法: python find_window_consts.py
"""
import pickle
import re
import sys

CACHE = r"C:\Users\lenov\malody_re\insns.pkl"

TARGETS = [45, 85, 130, 170]          # 实测槽位
ALT = [55, 95, 140, 180]              # 含 base=10 的版本
LEVEL_BASES = [10, 0, -10, -18, -26, -8, 8, 20]   # 可能的等级偏移

print("[*] loading %s ..." % CACHE)
insns = pickle.load(open(CACHE, 'rb'))
print("[*] %d insns" % len(insns))

# ---- 切成函数 ----
funcs = []
cur = None
for i, (a, m, ops) in enumerate(insns):
    is_pro = (m == 'stp' and ops.startswith('x29, x30')) or m == 'paciasp' or \
             (m == 'sub' and ops.startswith('sp, sp'))
    if is_pro:
        if cur is not None and i - cur[0] > 3:
            funcs.append((cur[1], cur[0], i))
        cur = (i, a)
if cur:
    funcs.append((cur[1], cur[0], len(insns)))
print("[*] %d functions" % len(funcs))

IMM = re.compile(r'#(-?0x[0-9a-fA-F]+|-?\d+)\s*$')


def last_imm(ops):
    m = IMM.search(ops)
    if not m:
        return None
    t = m.group(1)
    try:
        return int(t, 16) if t.startswith(('0x', '-0x')) else int(t)
    except ValueError:
        return None


def collect(lo, hi):
    """函数体内所有 mov/movz/movn 的立即数序列"""
    out = []
    for k in range(lo, hi):
        a, m, ops = insns[k]
        if m in ('mov', 'movz', 'movn'):
            v = last_imm(ops)
            if v is not None:
                out.append((k, a, m, ops, v))
    return out


print("\n=== A) 同时出现 45 和 85 和 130 的函数 (窗口设置嫌疑) ===")
hits_a = []
for (fs, i0, i1) in funcs:
    n = i1 - i0
    if n < 8 or n > 600:
        continue
    imms = collect(i0, i1)
    vals = set(v for (_, _, _, _, v) in imms)
    got = [t for t in TARGETS if t in vals]
    if len(got) >= 3:
        hits_a.append((fs, n, got, imms))
print("    命中: %d" % len(hits_a))
for fs, n, got, imms in hits_a[:15]:
    print("\n  --- 0x%08x  (%d insns)  含 %s ---" % (fs, n, got))
    for (k, a, m, ops, v) in imms:
        star = '  <<<' if v in TARGETS else ''
        print("    %08x  %-6s %-24s%s" % (a, m, ops, star))

print("\n=== B) 含 170 且含 (45|85|130) 的函数 ===")
hits_b = []
for (fs, i0, i1) in funcs:
    n = i1 - i0
    if n < 8 or n > 600:
        continue
    imms = collect(i0, i1)
    vals = set(v for (_, _, _, _, v) in imms)
    if 170 in vals and (45 in vals or 85 in vals or 130 in vals):
        hits_b.append((fs, n, sorted(vals & set(TARGETS))))
print("    命中: %d" % len(hits_b))
for fs, n, got in hits_b[:20]:
    print("    0x%08x  insns=%3d  含 %s" % (fs, n, got))

print("\n=== C) 含全部 4 个槽位常量的函数 (最强签名) ===")
full = [(fs, n) for (fs, i0, i1) in funcs
        if 8 <= i1 - i0 <= 600 and
        set(TARGETS) <= set(v for (_, _, _, _, v) in collect(i0, i1))]
print("    命中: %d" % len(full))
for fs, n in full[:20]:
    print("    0x%08x  insns=%3d" % (fs, n))

print("\n=== D) 含等级偏移候选 (10/0/-10/-18/-26) + 槽位常量的函数 ===")
for (fs, i0, i1) in funcs:
    n = i1 - i0
    if n < 8 or n > 600:
        continue
    imms = collect(i0, i1)
    vals = set(v for (_, _, _, _, v) in imms)
    if len(set(TARGETS) & vals) >= 2 and (vals & set([10, -10, -18, -26, 8])):
        print("    0x%08x  insns=%3d  slot=%s  shift=%s"
              % (fs, n, sorted(vals & set(TARGETS)),
                 sorted(vals & set([10, -10, -18, -26, 8]))))
