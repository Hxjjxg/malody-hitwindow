# -*- coding: utf-8 -*-
"""按"行为签名"在 libmalodycpp.so 里找判定函数 (arm64)。

桌面版 sub_535C40 的核心特征:
  - 返回 0x40000000 表示"无判定" (多处出现)
  - 计算 delta = noteTime - currentTime
  - 用 0x40(早) / 0x20(晚) 作为标志位
  - 返回 档位位(2/4/8/1) | 早晚位
  - 有 3~4 级 csel/比较链

打分找候选函数。"""
import struct
import capstone

PATH = r"C:\Users\lenov\malody_re\libmalodycpp.so"
data = open(PATH, 'rb').read()

e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_es = struct.unpack_from('<H', data, 0x3A)[0]
e_en = struct.unpack_from('<H', data, 0x3C)[0]
e_sx = struct.unpack_from('<H', data, 0x3E)[0]
secs = []
for i in range(e_en):
    o = e_shoff + i * e_es
    (n, t, f, a, off, sz, l, inf, al, e2) = struct.unpack_from('<IIQQQQIIQQ', data, o)
    secs.append(dict(n=n, t=t, f=f, a=a, off=off, sz=sz))
sh = secs[e_sx]
for s in secs:
    p = sh['off'] + s['n']
    e = data.index(b'\0', p)
    s['name'] = data[p:e].decode()

TEXT = [s for s in secs if s['name'] == '.text'][0]
BLOB = data[TEXT['off']:TEXT['off'] + TEXT['sz']]
BASE = TEXT['a']

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# ---- pass 1: decode everything, split into "functions" heuristically ----
insns = []          # (addr, mnemonic, op_str)
addr = BASE
end = BASE + len(BLOB)
bad = 0
while addr < end:
    off = addr - BASE
    progressed = False
    try:
        for insn in md.disasm(BLOB[off:], addr):
            progressed = True
            insns.append((insn.address, insn.mnemonic, insn.op_str))
            addr = insn.address + insn.size
    except capstone.CsError:
        pass
    if not progressed:
        addr += 4
        bad += 1
print("[*] decoded %d insns (skipped %d bad words)" % (len(insns), bad))

# function ranges: start at prologue (stp x29,x30 / paciasp / sub sp,sp)
funcs = []
cur = None
for i, (a, m, ops) in enumerate(insns):
    is_pro = (m == 'stp' and ops.startswith('x29, x30')) or m == 'paciasp' or \
             (m == 'sub' and ops.startswith('sp, sp')) or \
             (m == 'stp' and ops.startswith('x19, x20, [sp'))
    if is_pro:
        if cur is not None and i - cur[0] > 4:
            funcs.append((cur[1], cur[0], i))
        cur = (i, a)
if cur is not None:
    funcs.append((cur[1], cur[0], len(insns)))
print("[*] candidate functions: %d" % len(funcs))

# ---- pass 2: score ----
SENT = 0x40000000
results = []
for (fs, i0, i1) in funcs:
    n = i1 - i0
    if n < 8 or n > 400:
        continue
    body = insns[i0:i1]
    score = 0
    why = []
    has_sent = 0
    has_orr20 = has_orr40 = 0
    has_mov20 = has_mov40 = 0
    has_small = set()
    for (a, m, ops) in body:
        if m == 'mov' and ops.replace(' ', '').endswith('#0x40000000'):
            has_sent += 1
        if m == 'mov' and ops.strip().endswith('#0x20'):
            has_mov20 += 1
        if m == 'mov' and ops.strip().endswith('#0x40'):
            has_mov40 += 1
        if m == 'orr' and ops.strip().endswith('#0x20'):
            has_orr20 += 1
        if m == 'orr' and ops.strip().endswith('#0x40'):
            has_orr40 += 1
        if m == 'mov':
            for v in ('#2', '#4', '#8', '#1'):
                if ops.strip().endswith(v):
                    has_small.add(v)
    if has_sent:
        score += 4
        why.append('sent x%d' % has_sent)
    if has_orr20 or has_orr40:
        score += 3
        why.append('orr20/40=%d/%d' % (has_orr20, has_orr40))
    if has_mov20 and has_mov40:
        score += 3
        why.append('mov20&40')
    elif has_mov20 or has_mov40:
        score += 1
        why.append('mov20/40=%d/%d' % (has_mov20, has_mov40))
    if len(has_small) >= 3:
        score += 2
        why.append('small%s' % sorted(has_small))
    if n <= 120:
        score += 1
        why.append('small-fn')
    if score >= 6:
        results.append((score, fs, n, why))

results.sort(key=lambda r: -r[0])
print("\n[*] top candidates (score >= 6): %d" % len(results))
for score, fs, n, why in results[:25]:
    print("   score=%2d  func=0x%08x  insns=%3d  %s" % (score, fs, n, ' | '.join(why)))
