# -*- coding: utf-8 -*-
"""静态定位 libmalodycpp.so (arm64) 中的 JudgeKey 判定窗口常量。

桌面版已知: judgeObj[8..11] = 36/76/110/160 (= 0x24/0x4C/0x6E/0xA0),
            judgeObj[4] 基准 = 10 默认 (随 user_judge_level 缩放)。

三条独立判定路径:
  A) .rodata 字面量池: 24 00 00 00 4c 00 00 00 6e 00 00 00 a0 00 00 00
  B) .text 里连续 MOVZ: mov w?, #0x24 / #0x4c / #0x6e / #0xa0
  C) .text 里连续 STR 到 [x?, #0x20/#0x24/#0x28/#0x2c]

输出候选 RVA，供 ELF 虚拟地址换算 / objdump 反汇编确认。
"""
import struct
import sys

PATH = r"C:\Users\lenov\malody_re\libmalodycpp.so"

CONSTS = [0x24, 0x4C, 0x6E, 0xA0]

data = open(PATH, 'rb').read()
print("[*] %s  (%d bytes)" % (PATH, len(data)))

# ---------- ELF64 section headers ----------
assert data[:4] == b'\x7fELF', "not ELF"
is64 = data[4] == 2
assert is64, "expect ELF64"
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    (name, typ, flags, addr, offset, size,
     link, info, align, entsize) = struct.unpack_from('<IIQQQQIIQQ', data, off)
    secs.append(dict(name=name, typ=typ, flags=flags, addr=addr,
                     offset=offset, size=size))

shstr = secs[e_shstrndx]


def sname(n):
    s = shstr['offset'] + n
    e = data.index(b'\0', s)
    return data[s:e].decode('utf-8', 'replace')


for s in secs:
    s['sname'] = sname(s['name'])

exec_secs = [s for s in secs if s['flags'] & 0x4 and s['size']]
ro_secs = [s for s in secs if s['sname'] in ('.rodata', '.data.rel.ro', '.data')]

print("[*] sections: %d exec=%d" % (len(secs), len(exec_secs)))
for s in exec_secs:
    print("    exec  %-16s vaddr=0x%08x off=0x%08x size=0x%x"
          % (s['sname'], s['addr'], s['offset'], s['size']))

VTABLE_NOTE = []

# ---------- A) .rodata literal pool ----------
print("\n=== A) literal pool scan (any section) ===")
lit = struct.pack('<4I', *CONSTS)
pos = data.find(lit)
hits_a = []
while pos != -1:
    # map file offset -> vaddr
    va = None
    for s in secs:
        if s['offset'] <= pos < s['offset'] + s['size'] and s['typ'] != 8:
            va = s['addr'] + (pos - s['offset'])
            sec = s['sname']
            break
    hits_a.append((pos, va, sec if va is not None else '?'))
    pos = data.find(lit, pos + 1)
    if len(hits_a) > 40:
        break
print("    hits: %d" % len(hits_a))
for pos, va, sec in hits_a[:40]:
    print("    file=0x%08x  vaddr=%s  sec=%s"
          % (pos, ('0x%08x' % va) if va is not None else '?', sec))

# ---------- B) MOVZ sequence in .text ----------
print("\n=== B) MOVZ sequence scan in exec sections ===")
# movz w<rd>, #imm  ->  0x52800000 | (imm << 5) | rd
MOVZ = {}
for i, c in enumerate(CONSTS):
    MOVZ[0x52800000 | (c << 5)] = i
    MOVZ[(0x52800000 | (c << 5)) & 0xFFFFFFE0] = i
mask = 0xFFFFFFE0

hits_b = []
for s in exec_secs:
    blob = data[s['offset']:s['offset'] + s['size']]
    n = len(blob) & ~3
    # collect movz matches with their instruction index
    marks = []
    for o in range(0, n, 4):
        w = struct.unpack_from('<I', blob, o)[0]
        k = MOVZ.get(w & mask)
        if k is not None and (w & 0xFFE00000) == 0x52800000:
            marks.append((o // 4, k, w))
    # find windows: 4 kinds in ascending order within 40 instructions
    for a in range(len(marks)):
        need = 1
        seq = [marks[a]]
        last = marks[a][0]
        for b in range(a + 1, len(marks)):
            if marks[b][0] - last > 40:
                break
            if marks[b][1] == need:
                seq.append(marks[b])
                last = marks[b][0]
                need += 1
                if need == 4:
                    break
        if need == 4:
            va = s['addr'] + seq[0][0] * 4
            hits_b.append((s['sname'], va, seq[0][0] * 4, [x[2] for x in seq]))

print("    hits: %d" % len(hits_b))
seen_b = set()
for sec, va, off, ws in hits_b:
    key = va
    if key in seen_b:
        continue
    seen_b.add(key)
    print("    %s vaddr=0x%08x fileoff=0x%08x  movz=%s"
          % (sec, va, off, ' '.join('#0x%x' % ((w >> 5) & 0xFFFF) for w in ws)))

# ---------- C) STR sequence in .text ----------
print("\n=== C) STR [xN,#0x20/24/28/2c] sequence scan ===")
# str w<rt>, [x<rn>, #imm]  ->  0xB9000000 | ((imm>>2) << 10) | (rn << 5) | rt
hits_c = []
for s in exec_secs:
    blob = data[s['offset']:s['offset'] + s['size']]
    n = len(blob) & ~3
    marks = []
    for o in range(0, n, 4):
        w = struct.unpack_from('<I', blob, o)[0]
        if (w & 0xFFC00000) == 0xB9000000:
            imm = (w >> 10) & 0xFFF
            if imm in (8, 9, 10, 11):
                marks.append((o // 4, imm - 8, w))
    for a in range(len(marks)):
        need = 1
        seq = [marks[a]]
        last = marks[a][0]
        rn0 = (marks[a][2] >> 5) & 31
        rt0 = marks[a][2] & 31
        for b in range(a + 1, len(marks)):
            if marks[b][0] - last > 12:
                break
            if ((marks[b][2] >> 5) & 31) == rn0 and (marks[b][2] & 31) == rt0 \
                    and marks[b][1] == need:
                seq.append(marks[b])
                last = marks[b][0]
                need += 1
                if need == 4:
                    break
        if need == 4:
            hits_c.append((s['sname'], s['addr'] + seq[0][0] * 4,
                           seq[0][0] * 4, rn0, rt0))

print("    hits: %d" % len(hits_c))
seen_c = set()
for sec, va, off, rn, rt in hits_c:
    if va in seen_c:
        continue
    seen_c.add(va)
    print("    %s vaddr=0x%08x fileoff=0x%08x  str w%d,[x%d,#0x20..2c]"
          % (sec, va, off, rt, rn))

print("\n[*] done")
