# -*- coding: utf-8 -*-
"""arm64 反汇编器 (带注释): 解析 adrp+add -> 字符串, bl -> 目标函数。

用法:
  python arm64_dis.py <start_hex> [end_hex] [--func]   # --func: 自动向前找函数头
"""
import struct
import sys
import capstone

PATH = r"C:\Users\lenov\malody_re\libmalodycpp.so"
data = open(PATH, 'rb').read()

e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    (n, t, f, a, off, sz, l, inf, al, es) = struct.unpack_from('<IIQQQQIIQQ', data, o)
    secs.append(dict(n=n, t=t, f=f, a=a, off=off, sz=sz))
sh = secs[e_shstrndx]
for s in secs:
    p = sh['off'] + s['n']
    e = data.index(b'\0', p)
    s['name'] = data[p:e].decode()

TEXT = [s for s in secs if s['name'] == '.text'][0]
BLOB = data[TEXT['off']:TEXT['off'] + TEXT['sz']]
BASE = TEXT['a']


def va2off(va):
    for s in secs:
        if s['t'] != 8 and s['sz'] and s['a'] <= va < s['a'] + s['sz']:
            return s['off'] + (va - s['a']), s['name']
    return None, None


def read_cstr(va, maxlen=80):
    o, sec = va2off(va)
    if o is None:
        return None
    e = data.find(b'\0', o, o + maxlen)
    if e == -1:
        return None
    raw = data[o:e]
    if not raw or any(c < 9 or (13 < c < 32) or c > 126 for c in raw):
        return None
    return raw.decode('ascii')


md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True
R = capstone.arm64

PROLOGUES = ('stp', 'sub', 'str', 'paciasp', 'bti')


def find_func_start(va, back=0x800):
    """向前找函数头: 常见 prologue 且前一指令是 ret/brk/b 等."""
    cur = va
    best = va
    while cur > va - back and cur > BASE:
        cur -= 4
        o = cur - BASE
        if o < 0:
            break
        try:
            ins = next(md.disasm(BLOB[o:o + 4], cur))
        except StopIteration:
            continue
        if ins.mnemonic in ('stp', 'sub', 'str', 'paciasp') and \
                ins.op_str.startswith(('x29, x30', 'sp, sp', 'x29, x30', 'x30, x29')):
            return cur
        if ins.mnemonic == 'sub' and 'sp, sp' in ins.op_str:
            return cur
    return best


def disasm_range(start, end, label=None):
    if label:
        print("\n===== %s  [0x%08x .. 0x%08x] =====" % (label, start, end))
    else:
        print("\n===== 0x%08x .. 0x%08x =====" % (start, end))
    o = start - BASE
    if o < 0:
        print("  (outside .text)")
        return
    adrp_page = {}
    addrs = {}
    cur = start
    while cur < end:
        o = cur - BASE
        try:
            insn = next(md.disasm(BLOB[o:o + 4], cur))
        except StopIteration:
            print("  %08x  .word 0x%08x" % (cur, struct.unpack_from('<I', BLOB, o)[0]))
            cur += 4
            adrp_page.clear()
            continue
        m = insn.mnemonic
        cmt = ''
        if m == 'adrp':
            raw = struct.unpack_from('<I', BLOB, o)[0]
            imm = (((raw >> 5) & 0x7FFFF) << 2) | ((raw >> 29) & 0x3)
            if imm & (1 << 20):
                imm -= (1 << 21)
            pg = (cur & ~0xFFF) + (imm << 12)
            adrp_page[insn.operands[0].reg] = pg
        elif m == 'add' and len(insn.operands) == 3:
            o0, o1, o2 = insn.operands
            if o0.type == R.ARM64_OP_REG and o1.type == R.ARM64_OP_REG and \
                    o0.reg == o1.reg and o2.type == R.ARM64_OP_IMM:
                pg = adrp_page.get(o1.reg)
                if pg is not None:
                    t = pg + o2.imm
                    s = read_cstr(t)
                    if s is not None:
                        cmt = '  ; "%s"' % s
                    else:
                        sec = va2off(t)[1]
                        cmt = '  ; -> 0x%x (%s)' % (t, sec)
        elif m in ('bl', 'b') and insn.operands and \
                insn.operands[0].type == R.ARM64_OP_IMM:
            t = insn.operands[0].imm
            addrs.setdefault(t, 0)
            addrs[t] += 1
            cmt = '  ; -> 0x%x' % t
        try:
            for w in insn.regs_access()[1]:
                if w in adrp_page and m != 'adrp':
                    del adrp_page[w]
        except Exception:
            adrp_page.clear()
        print("  %08x  %-8s %s%s" % (cur, m, insn.op_str, cmt))
        cur += insn.size


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    start = int(args[0], 16)
    ffunc = '--func' in sys.argv
    if ffunc:
        start = find_func_start(start)
        print("[*] function start = 0x%08x" % start)
    if len(args) > 1:
        end = int(args[1], 16)
    else:
        end = start + 0x200
    disasm_range(start, end)
