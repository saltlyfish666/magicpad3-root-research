# -*- coding: utf-8 -*-
"""Experiment dashboard: summarize each app_root run (outcome + nofire + shot
counts) and dcshot prep_tries series, segmented by known experiment windows."""
import glob
import os
import re
from datetime import datetime

LOGDIR = r"D:\file\文档\workbuddy\2026-10-13-11-14-12\auto_root_logs"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def runs():
    out = []
    for p in sorted(glob.glob(os.path.join(LOGDIR, "app_root_*.log"))):
        raw = open(p, "rb").read().decode("utf-8", "replace")
        name = os.path.basename(p)
        shots_fire = len(re.findall(r"本轮 miss", raw))
        hits = len(re.findall(r"ROOT 成功", raw))
        nofire = len(re.findall(r"找不到「一键部署执行」按钮", raw))
        nofire_fixed = len(re.findall(r"重启 GhostLock App 后重试", raw))
        jams = len(re.findall(r"240s 无结论", raw))
        panics = len(re.findall(r"异常重启|判定内核 panic", raw))
        v2 = "app_root" in name and raw.find("[v2]") >= 0
        ts = re.match(r"app_root_(\d{4})_(\d{6})", name)
        t = f"{ts.group(1)}-{ts.group(2)[:2]}:{ts.group(2)[2:4]}:{ts.group(2)[4:]}" if ts else "?"
        out.append((name, t, shots_fire, hits, nofire, nofire_fixed, jams, panics, v2))
    return out


print(f"{'run':30s} {'start':14s} {'miss':>5s} {'hit':>4s} {'nofire':>6s} {'fixed':>5s} {'jam':>4s} {'panic':>5s} v2")
for r in runs():
    print(f"{r[0]:30s} {r[1]:14s} {r[2]:5d} {r[3]:4d} {r[4]:6d} {r[5]:5d} {r[6]:4d} {r[7]:5d} {'Y' if r[8] else ''}")

print("\n== dcshot prep series (per shot) ==")
rows = []
for path in sorted(glob.glob(os.path.join(LOGDIR, "dcshot_*.log"))):
    name = os.path.basename(path)
    m = re.match(r"dcshot_(\d{4})_(\d{6})_(\w+)\.log", name)
    tag = m.group(3) if m else "?"
    t = f"{m.group(1)[:2]}:{m.group(1)[2:]}:{m.group(2)[:2]}" if m else "?"
    raw = open(path, "rb").read().decode("utf-8", "replace")
    ls = [ANSI.sub("", x).strip() for x in raw.splitlines()]
    fails_before_valid = None
    total = 0
    exploit_att = 0
    restarts = 0
    physrw = None
    for l in ls:
        m2 = re.search(r"exploit attempt=(\d+)/(\d+) pid=", l)
        if m2:
            exploit_att = int(m2.group(1))
            if exploit_att > 1:
                restarts += 1
            continue
        m3 = re.search(r"kernel page prepare mode=\d+ attempt=\d+/\d+ elapsed_ms=(\d+) base=(\S+)", l)
        if m3:
            total += 1
            if m3.group(2) != "0000000000000000" and fails_before_valid is None:
                fails_before_valid = total - 1
        if "pipe physrw" in l:
            physrw = l
    hit = bool(physrw and "done=1" in physrw)
    rows.append((t, tag, fails_before_valid, total, exploit_att, restarts, hit))

print(f"{'time':9s} {'tag':6s} {'fails>valid':>11s} {'prep_total':>10s} {'att':>4s} {'rst':>3s} hit")
for r in rows:
    fb = "-" if r[2] is None else str(r[2])
    print(f"{r[0]:9s} {r[1]:6s} {fb:>11s} {r[3]:10d} {r[4]:4d} {r[5]:3d} {r[6]}")

vals = [r[2] for r in rows if r[2] is not None]
if vals:
    vals_sorted = sorted(vals)
    med = vals_sorted[len(vals_sorted) // 2]
    print(f"\nprep_fails_before_valid: n={len(vals)} mean={sum(vals)/len(vals):.1f} median={med} values={vals}")
