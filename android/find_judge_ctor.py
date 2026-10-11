# -*- coding: utf-8 -*-
"""找 arm64 判定对象的构造函数 + 列出所有判定函数。

arm64 judge 对象布局 (从判定函数反推):
  +0x20 base     +0x30 best     +0x34 cool     +0x38 good     +0x3c early-cutoff
构造函数 = 向 [x?, #0x20/#0x30/#0x34/#0x38/#0x3c] 连续写立即数的函数。
判定函数 = 含 ldr [x0,#0x20] + ldr [x0,#0x3c] + 0x40000000 + csel/csinc 链。
"""
import struct
import pickle
import os
import capstone

PATH = r"C:\Users\lenov\malody_re\libmalodycpp.so"
CACHE = r"C:\Users\lenov\malody_re\insns.pkl"

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

if os.path.exists(CACHE):
    insns = pickle.load(open(CACHE, 'rb'))
    print("[*] loaded %d insns from cache" % len(insns))
else:
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    insns = []
    addr = BASE
    end = BASE + len(BLOB)
    while addr < end:
        off = addr - BASE
        prog = False
        try:
            for insn in md.disasm(BLOB[off:], addr):
                prog = True
                insns.append((insn.address, insn.mnemonic, insn.op_str))
                addr = insn.address + insn.size
        except capstone.CsError:
            pass
        if not prog:
            addr += 4
    pickle.dump(insns, open(CACHE, 'wb'))
    print("[*] decoded %d insns (cached)" % len(insns))

# ---- function splitting ----
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
print("[*] functions: %d" % len(funcs))

STR_OFFS = {0x30: 12, 0x34: 13, 0x38: 14, 0x3c: 15, 0x20: 8}


def parse_str(ops):
    """'w8, [x0, #0x30]' -> (rt, rn, off)"""
    try:
        dst, rest = ops.split(',', 1)
        rest = rest.strip()
        if not rest.startswith('['):
            return None
        inner = rest[1:rest.index(']')]
        parts = [p.strip() for p in inner.split(',')]
        rn = parts[0]
        off = int(parts[1].lstrip('#'), 16) if len(parts) > 1 else 0
        return dst.strip(), rn, off
    except Exception:
        return None


print("\n=== A) 构造函数候选 (写 [xN,#0x20/0x30/0x34/0x38/0x3c]) ===")
ctor_hits = []
for (fs, i0, i1) in funcs:
    n = i1 - i0
    if n < 6 or n > 300:
        continue
    offs = {}
    for idx in range(i0, i1):
        a, m, ops = insns[idx]
        if m != 'str':
            continue
        r = parse_str(ops)
        if not r:
            continue
        rt, rn, off = r
        if off in STR_OFFS:
            offs.setdefault(off, []).append((idx, rt, rn))
    if len(offs) >= 4 and 0x30 in offs and 0x3c in offs:
        ctor_hits.append((fs, n, offs))

print("    candidates: %d" % len(ctor_hits))
for fs, n, offs in ctor_hits[:12]:
    print("\n  --- ctor? 0x%08x (%d insns) ---" % (fs, n))
    for idx in range(max(0, fs - BASE if False else 0), 0):
        pass
    # print the prologue window of this function
    start_i = None
    for (f2, j0, j1) in funcs:
        if f2 == fs:
            start_i = j0
            break
    if start_i is None:
        continue
    for k in range(start_i, min(start_i + 70, start_i + n)):
        a, m, ops = insns[k]
        r = parse_str(ops) if m == 'str' else None
        tag = ''
        if r and r[2] in STR_OFFS:
            tag = '   <<< +0x%x' % r[2]
        if m in ('str', 'mov', 'movz', 'movk', 'add', 'adrp') or tag:
            print("    %08x  %-8s %s%s" % (a, m, ops, tag))

print("\n=== B) 判定函数 (ldr [x0,#0x20] + [x0,#0x3c] + 0x40000000) ===")
jf = []
for (fs, i0, i1) in funcs:
    n = i1 - i0
    if n < 15 or n > 250:
        continue
    has20 = has3c = has_sent = has_csel = False
    for k in range(i0, i1):
        a, m, ops = insns[k]
        if m == 'ldr' and '[x0, #0x20]' in ops:
            has20 = True
        if m == 'ldr' and '[x0, #0x3c]' in ops:
            has3c = True
        if m == 'mov' and ops.strip().endswith('#0x40000000'):
            has_sent = True
        if m in ('csel', 'csinc'):
            has_csel = True
    if has20 and has3c and has_sent:
        jf.append((fs, n, has_csel))
print("    judge-like functions: %d" % len(jf))
for fs, n, hc in jf:
    print("    0x%08x  insns=%3d  csel=%s" % (fs, n, hc))
