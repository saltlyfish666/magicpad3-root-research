# -*- coding: utf-8 -*-
"""Compare prep_fails_before_valid (memory-state probe) between experiment windows,
plus Mann-Whitney U test (no scipy dependency).

Usage: edit WINDOWS below with actual run windows (start,end inclusive HH:MM:SS).
"""
import glob
import os
import re
from datetime import datetime

LOGDIR = r"D:\file\文档\workbuddy\2026-10-13-11-14-12\auto_root_logs"

# ---- windows (fill after runs) ----
WINDOWS = {}  # label -> (start "HH:MM:SS", end "HH:MM:SS") of 10-15 Oct night


def shots():
    rows = []
    for path in sorted(glob.glob(os.path.join(LOGDIR, "dcshot_*.log"))):
        name = os.path.basename(path)
        m = re.match(r"dcshot_(\d{4})_(\d{6})_(\w+)\.log", name)
        if not m:
            continue
        # group(1)=MMDD group(2)=HHMMSS -> t="MMDD HH:MM:SS" (sortable within one night)
        t = f"{m.group(1)} {m.group(2)[:2]}:{m.group(2)[2:4]}:{m.group(2)[4:6]}"
        tag = m.group(3)
        raw = open(path, "rb").read().decode("utf-8", "replace")
        fails = None
        total = 0
        valid = False
        physrw = None
        attempt = 1
        for l in raw.splitlines():
            ma = re.search(r"exploit attempt=(\d+)/\d+ pid=", l)
            if ma:
                attempt = int(ma.group(1))
                continue
            mp = re.search(r"kernel page prepare mode=\d+ attempt=\d+/\d+ elapsed_ms=\d+ base=(\S+)", l)
            if mp:
                total += 1
                if mp.group(1) != "0000000000000000":
                    if not valid:
                        fails = total - 1
                        valid = True
            if "pipe physrw" in l:
                physrw = l
        hit = bool(physrw and "done=1" in physrw)
        rows.append({"t": t, "tag": tag, "fails": fails, "total": total,
                     "attempt": attempt, "hit": hit})
    return rows


def mannwhitney(a, b):
    """two-sided normal approximation"""
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return None
    ranked = sorted([(x, 0) for x in a] + [(x, 1) for x in b])
    # average ranks
    ranks = [0] * len(ranked)
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(ranks, ranked) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    u = min(u1, n1 * n2 - u1)
    mu = n1 * n2 / 2
    sd = (n1 * n2 * (n1 + n2 + 1) / 12) ** 0.5
    if sd == 0:
        return 1.0
    z = (u - mu) / sd
    # normal two-sided p
    p = 2 * (1 - 0.5 * (1 + abs(z) / (2 ** 0.5) * 0 + 0) )  # placeholder replaced below
    # use erf approximation
    import math
    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    return u, z, p


def summarize(rows, label):
    vals = [r["fails"] for r in rows if r["fails"] is not None]
    nofind = sum(1 for r in rows if r["fails"] is None)
    hits = sum(1 for r in rows if r["hit"])
    total = len(rows)
    if vals:
        s = sorted(vals)
        med = s[len(s) // 2]
        mean = sum(vals) / len(vals)
        mx = max(vals)
    else:
        med = mean = mx = None
    print(f"{label:24s} shots={total:3d} hits={hits} prep_valid={len(vals)} nofind={nofind} "
          f"fails mean={mean if mean is None else round(mean,2)} median={med} max={mx} values={vals}")
    return vals


def main():
    rows = shots()
    print(f"total dcshots: {len(rows)}")
    all_vals = summarize(rows, "ALL")
    print()
    if not WINDOWS:
        # default: split by file mtime isn't known; print with time only
        print("time       tag     fails total attempt hit")
        for r in rows:
            print(f"{r['t']}  {r['tag']:6s} {str(r['fails']):>5s} {r['total']:5d} {r['attempt']:7d} {r['hit']}")
        return
    groups = {}
    for lbl, (s, e) in WINDOWS.items():
        groups[lbl] = [r for r in rows if s <= r["t"] <= e]
    res = {}
    for lbl, rs in groups.items():
        res[lbl] = summarize(rs, lbl)
    labels = list(res)
    if len(labels) >= 2 and res[labels[0]] and res[labels[1]]:
        u = mannwhitney(res[labels[0]], res[labels[1]])
        if u:
            print(f"\nMann-Whitney {labels[0]} vs {labels[1]}: U={u[0]:.1f} z={u[1]:.2f} p={u[2]:.4f}")


if __name__ == "__main__":
    main()
