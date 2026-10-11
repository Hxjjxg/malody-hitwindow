# -*- coding: utf-8 -*-
"""arm64 xref finder (resumable): 定位 libmalodycpp.so 里引用目标字符串的代码。

PIC 字符串引用: adrp xN, page + add xN, xN, #off
  adrp 目标页 = (pc & ~0xFFF) + (sign_extend21((immhi<<2)|immlo) << 12)
"""
import struct
import capstone

PATH = r"C:\Users\lenov\malody_re\libmalodycpp.so"
TARGETS = [b"judge-%d", b"user_judge_level", b"hit-slow", b"judge-glow.png",
           b"_judge-1", b"_judge-2"]

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

text = [s for s in secs if s['name'] == '.text'][0]
blob = data[text['off']:text['off'] + text['sz']]
base = text['a']
print("[*] .text vaddr=0x%x size=0x%x" % (base, text['sz']))

str_va = {}
for tgt in TARGETS:
    pos = data.find(tgt)
    if pos == -1:
        print("[str] %-18s NOT FOUND" % tgt.decode())
        continue
    for s in secs:
        if s['t'] != 8 and s['sz'] and s['off'] <= pos < s['off'] + s['sz']:
            str_va[tgt.decode()] = s['a'] + (pos - s['off'])
            print("[str] %-18s vaddr=0x%08x sec=%s"
                  % (tgt.decode(), s['a'] + (pos - s['off']), s['name']))
            break
want = set(str_va.values())
rev = {v: k for k, v in str_va.items()}

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True
R = capstone.arm64

adrp_page = {}
hits = []
n_insn = 0
bad = 0
addr = base
end = base + len(blob)

while addr < end:
    off = addr - base
    progressed = False
    try:
        for insn in md.disasm(blob[off:], addr):
            progressed = True
            n_insn += 1
            m = insn.mnemonic
            if m == 'adrp' and insn.operands:
                raw = struct.unpack_from('<I', blob, insn.address - base)[0]
                imm = (((raw >> 5) & 0x7FFFF) << 2) | ((raw >> 29) & 0x3)
                if imm & (1 << 20):
                    imm -= (1 << 21)
                adrp_page[insn.operands[0].reg] = (insn.address & ~0xFFF) + (imm << 12)
            elif m == 'add' and len(insn.operands) == 3:
                o0, o1, o2 = insn.operands
                if o0.type == R.ARM64_OP_REG and o1.type == R.ARM64_OP_REG \
                        and o0.reg == o1.reg and o2.type == R.ARM64_OP_IMM:
                    pg = adrp_page.get(o1.reg)
                    if pg is not None:
                        t = pg + o2.imm
                        if t in want:
                            hits.append((insn.address, t))
            # 失效: 任何写寄存器的指令清掉它的 adrp 缓存
            try:
                for w in insn.regs_access()[1]:
                    if w in adrp_page and m != 'adrp':
                        del adrp_page[w]
            except Exception:
                adrp_page.clear()
            addr = insn.address + insn.size
    except capstone.CsError:
        pass
    if not progressed:
        addr += 4
        bad += 1
        adrp_page.clear()

print("\n[*] decoded instructions: %d   (skipped %d bad words)" % (n_insn, bad))
print("[*] adrp+add hits: %d" % len(hits))
for pc, t in hits:
    print("    pc=0x%08x -> %-18s (0x%08x)   [func?]" % (pc, rev.get(t, '?'), t))

print("\n[*] pointer-table refs in data sections:")
found = 0
for s in secs:
    if s['name'] not in ('.data.rel.ro', '.data', '.rodata', '.data.rel.ro.local'):
        continue
    b = data[s['off']:s['off'] + s['sz']]
    for tgt, va in str_va.items():
        pkt = struct.pack('<Q', va)
        st = 0
        while True:
            p = b.find(pkt, st)
            if p == -1:
                break
            st = p + 1
            found += 1
            if found <= 40:
                print("    %s: 0x%08x holds ptr -> %s" % (s['name'], s['a'] + p, tgt))
print("    total ptr refs: %d" % found)
print("[*] done")
