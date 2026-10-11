# -*- coding: utf-8 -*-
"""Find the |d| boundaries where the judge 'low' tier changes in judge_log.txt.

Each JUDGE line: d (ms timing offset), time (note time, resets per song),
mask (0x4X = early/d<0, 0x2X = late/d>0, low nibble = tier), low (judge tier).

Outputs: global tier stats, optimal split thresholds between adjacent quality
tiers, split per song (time-column resets) and per early/late sign.
"""
import re, collections, statistics

PATH = r"C:\Users\lenov\malody_re\judge_log.txt"
REC = re.compile(r"JUDGE down d=(-?\d+)ms time=(\d+) mask=\w+ low=(\d+)")

records = []  # (line_no, d, time, low)
with open(PATH, encoding="utf-8", errors="replace") as f:
    for ln, line in enumerate(f, 1):
        m = REC.search(line)
        if m:
            records.append((ln, int(m.group(1)), int(m.group(2)), int(m.group(3))))


def split_songs(recs):
    """Split into contiguous songs where the time column resets backwards."""
    groups, cur = [], [recs[0]]
    for r in recs[1:]:
        if r[2] < cur[-1][2] - 50:          # time jumped back -> new song
            groups.append(cur)
            cur = [r]
        else:
            cur.append(r)
    groups.append(cur)
    return groups


def quality_order(recs):
    """Tiers from best (smallest median |d|) to worst."""
    by_low = collections.defaultdict(list)
    for _, d, _, low in recs:
        by_low[low].append(abs(d))
    return sorted(by_low, key=lambda low: statistics.median(by_low[low]))


def boundaries(recs):
    """Optimal |d| threshold between each adjacent pair of quality tiers."""
    by_low = collections.defaultdict(list)
    for _, d, _, low in recs:
        by_low[low].append(abs(d))
    lows = quality_order(recs)
    out = []
    for a, b in zip(lows, lows[1:]):
        va, vb = sorted(by_low[a]), sorted(by_low[b])
        cand = sorted(set(va) | set(vb))
        best = min(
            (sum(1 for v in va if v > th) + sum(1 for v in vb if v <= th), th)
            for th in cand
        )
        out.append((a, b, va[-1], vb[0], best[1], best[0], len(va) + len(vb)))
    return out


def show(title, recs):
    by_low = collections.defaultdict(list)
    for _, d, _, low in recs:
        by_low[low].append(abs(d))
    print(f"\n=== {title}  (n={len(recs)}) ===")
    print("  low |   n | min|d| | max|d| | median")
    for low in sorted(by_low):
        v = by_low[low]
        print(f"  {low:3d} | {len(v):4d} | {min(v):6d} | {max(v):6d} | {statistics.median(v):6.1f}")
    for a, b, max_a, min_b, th, wrong, n in boundaries(recs):
        print(f"  boundary low={a}->low={b}: best |d| split = {th} ms "
              f"(max|d|low={a}={max_a}, min|d|low={b}={min_b}, misclassified={wrong}/{n})")


show("GLOBAL", records)

songs = split_songs(records)
print(f"\n\n--- {len(songs)} song sections detected (time column resets) ---")
for idx, s in enumerate(songs, 1):
    rng = (s[0][0], s[-1][0])
    show(f"SONG {idx} (log lines {rng[0]}-{rng[1]})", s)

for label, sel in (("EARLY d<0", [r for r in records if r[1] < 0]),
                   ("LATE  d>0", [r for r in records if r[1] > 0])):
    show(label, sel)
