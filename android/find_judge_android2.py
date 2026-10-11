# -*- coding: utf-8 -*-
"""柔性扫描: 在 libmalodycpp.so 里找判定窗口常量序列, 允许任意步长(4/8字节)。

候选常量集(来自桌面版各 Judge 类构造函数):
  JudgeKey      : 36 / 76 / 110 / 160
  JudgeKeyFair  : 45 / 85 / 120 / 170
  JudgeSlide    : 36 / 76 / 110 / 160
  JudgeJubeat   : 40 / 80 / 160 / 383
  JudgePad      : [12..15] = 45 / 85 / 230 / 160

同时对每个命中检查 [4] 基准候选 (20/10/0/-8/-16 或 10) 是否在附近。
"""
import struct

PATH = r"C:\Users\lenov\malody_re\libmalodycpp.so"
data = open(PATH, 'rb').read()

SETS = {
    'JudgeKey/Slide': [36, 76, 110, 160],
    'JudgeKeyFair':   [45, 85, 120, 170],
    'JudgeJubeat':    [40, 80, 160, 383],
}

# ---------- ELF section map ----------
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
secs = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    (name, typ, flags, addr, offset, size, link, info, align, entsize) = \
        struct.unpack_from('<IIQQQQIIQQ', data, off)
    secs.append(dict(name=name, typ=typ, flags=flags, addr=addr,
                     offset=offset, size=size, align=align))
shstr = secs[e_shstrndx]
for s in secs:
    p = shstr['offset'] + s['name']
    e = data.index(b'\0', p)
    s['sname'] = data[p:e].decode('utf-8', 'replace')


def off2va(o):
    for s in secs:
        if s['typ'] != 8 and s['size'] and s['offset'] <= o < s['offset'] + s['size']:
            return s['addr'] + (o - s['offset']), s['sname']
    return None, '?'


print("[*] %d bytes, %d sections" % (len(data), len(secs)))

# ---------- brute-force dword sequence search with variable stride ----------
MAXGAP = 64          # 常量之间最大字节距离
STRIDES = (4, 8, 16)


def find_seq(vals):
    out = []
    for stride in STRIDES:
        first = struct.pack('<I', vals[0])
        start = 0
        while True:
            p = data.find(first, start)
            if p == -1:
                break
            start = p + 1
            ok = True
            for k in range(1, len(vals)):
                q = p + stride * k
                if q + 4 > len(data) or struct.unpack_from('<I', data, q)[0] != vals[k]:
                    ok = False
                    break
            if ok:
                out.append((p, stride))
    return out


for name, vals in SETS.items():
    print("\n=== %s : %s ===" % (name, vals))
    hits = find_seq(vals)
    print("    raw hits: %d" % len(hits))
    shown = set()
    for p, stride in hits[:60]:
        va, sec = off2va(p)
        key = (va, stride)
        if key in shown:
            continue
        shown.add(key)
        # 看前面是否有基准 [4] 候选
        pre = []
        for back in range(4, 0x30, 4):
            if p - back < 0:
                break
            v = struct.unpack_from('<i', data, p - back)[0]
            if v in (20, 10, 0, -8, -16, -6, -12, 6, 12, 14):
                pre.append((back, v))
        print("    file=0x%08x vaddr=0x%08x sec=%-12s stride=%d  pre=%s"
              % (p, va if va else 0, sec, stride, pre))

# ---------- 单独搜: judge 结构 [4] 与 [8..11] 的完整 0x30 字节快照 ----------
print("\n=== full struct snapshot scan (0x30 bytes, any stride) ===")
BASES = (20, 10, 0, -8, -16)
cnt = 0
for base in BASES:
    for vals in (SETS['JudgeKey/Slide'], SETS['JudgeKeyFair']):
        for stride in (4,):
            for p in range(0, len(data) - 0x40, 4):
                if struct.unpack_from('<i', data, p)[0] != base:
                    continue
                # [8] 距 [4] 通常 0x10 -> 尝试 offset 0x10 / 0x20 / 0x40
                for d in (0x10, 0x20, 0x40, 0x18):
                    if p + d + 16 > len(data):
                        continue
                    if list(struct.unpack_from('<4I', data, p + d)) == \
                            [v & 0xFFFFFFFF for v in vals]:
                        va, sec = off2va(p)
                        print("    base=%d [4]@file=0x%08x vaddr=0x%08x sec=%s "
                              "const@+0x%x = %s" % (base, p, va if va else 0, sec, d, vals))
                        cnt += 1
print("    total: %d" % cnt)
print("\n[*] done")
