#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forensic_mine.py — 只读日志法证：找 hit/miss 在「写入之前/之时」的判别信号。
新建输出文件 forensic_mine_out.txt，不改任何既有文件。
"""
import os, re, glob, io, collections

BASE = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy"
AUTO = r"D:\file\文档\workbuddy\2026-10-13-11-14-12\auto_root_logs"
OUT = os.path.join(BASE, "analysis", "forensic_mine_out.txt")

ANSI = re.compile(r"\x1b\[[0-9;]*m")

def read(p):
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return [ANSI.sub("", ln.rstrip("\n")) for ln in f]

files = []

def add(p, label, group):
    if os.path.exists(p):
        files.append((p, label, group))

add(os.path.join(BASE, "hitsample", "hit_dc_ksu.log"),  "HIT",  "golden")
add(os.path.join(BASE, "hitsample", "hit2_dc_ksu.log"), "HIT",  "golden")
add(os.path.join(BASE, "logstudy", "tuned_fire.log"),   "HIT",  "golden_dup")
add(os.path.join(BASE, "logstudy", "dc_ksu.log"),       "MISS", "golden")
for p in sorted(glob.glob(os.path.join(AUTO, "dcshot_*.log"))):
    add(p, "JAM" if p.endswith("_jam.log") else "MISS", "dcshot")
for p in sorted(glob.glob(os.path.join(AUTO, "app_root_*.log"))):
    add(p, "UNK", "app_root")

def verdict(lines):
    joined = "\n".join(lines)
    m = re.search(r"pipe physrw pid=\d+ done=(\d) root=(\d)[^\n]*read_ok=(\d) write_ok=(\d)", joined)
    if m:
        lab = "HIT" if (m.group(1) == "1" and m.group(2) == "1") else "MISS"
        return lab, m.group(0)
    if re.search(r"root direct: selinux write ok=1", joined):
        return "HIT", "root direct: selinux write ok=1 1->0"
    if re.search(r"ALREADY_RAN_THIS_BOOT", joined):
        return "SKIP", "ALREADY_RAN_THIS_BOOT"
    if re.search(r"app fops slide attempt=\d+/\d+ triggered=\d+ verified=0 step=6", joined):
        return "MISS", "triggered=1 verified=0 step=6"
    return "UNK", "-"

KEYS = ["step", "verified", "triggered", "dirty", "errno", "attempt", "done", "root",
        "read_ok", "write_ok", "sched_ok", "waiter_ok", "write_window", "consume_calls",
        "child_result", "status", "ret", "canon", "slot", "ok", "replaced", "mode",
        "elapsed_ms", "waited_ms", "nr", "wp", "reaped", "child_done", "fine_ticks",
        "counter", "entry", "uid", "euid", "enforce", "sig_enforce"]

FIRE_MARK = re.compile(r"p0 physical write|cfi restoring|cfi misc_fops restore")

def phase_split(lines):
    for i, ln in enumerate(lines):
        if FIRE_MARK.search(ln):
            return lines[:i], lines[i:]
    return lines, []

def kv(lines, keys):
    out = collections.defaultdict(collections.Counter)
    for ln in lines:
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)=([^\s,;|]+)", ln):
            k, v = m.group(1), m.group(2)
            if k in keys:
                out[k][v] += 1
    return out

def feats(lines):
    j = "\n".join(lines)
    f = collections.OrderedDict()
    f["prep_fail_lines"] = len(re.findall(r"prepare_kernel_page retry \d+/\d+", j))
    f["prep_gave_up"] = len(re.findall(r"prepare_kernel_page did not find", j))
    f["mm_leak_failed"] = len(re.findall(r"KernelSnitch mm_struct leak failed", j))
    f["mm_leaked"] = len(re.findall(r"\bmm leaked=", j))
    f["resize_softfail"] = len(re.findall(r"resize_pipe_slots soft-fail", j))
    f["exploit_attempt_lines"] = len(re.findall(r"\bexploit attempt=\d+/\d+ ", j))
    f["max_prep_attempt"] = max([int(x) for x in re.findall(r"kernel page prepare mode=\d attempt=(\d+)/", j)] or [0])
    f["pselect_blocked"] = len(re.findall(r"slide pselect blocked", j))
    f["resencode"] = len(re.findall(r"res-encode consumer firing", j))
    f["write_geom"] = len(re.findall(r"WRITE-GEOM ", j))
    f["configfs_selfcheck_ok"] = len(re.findall(r"preopen configfs selfcheck ret=0", j))
    f["collisions_found"] = len(re.findall(r"found \d+ collisisons", j))
    m = re.search(r"quiet window seconds=(\d+)", j)
    f["quiet_window_sec"] = m.group(1) if m else "-"
    m = re.search(r"uptime_at_launch=(\d+)", j)
    f["uptime_at_launch"] = m.group(1) if m else "-"
    m = re.search(r"waiting for boot allocator quiet window seconds=\d+ uptime=(\d+)", j)
    f["uptime_at_quiet"] = m.group(1) if m else "-"
    return f

buf = io.StringIO()
w = lambda *a: print(*a, file=buf)

w("语料清单（label=由日志内容判读；name=文件名标签）")
w("=" * 110)
rows = []
for p, flab, grp in files:
    lines = read(p)
    v, ev = verdict(lines)
    rows.append((p, flab, v, grp, len(lines), ev))
    w("%-34s name=%-5s content=%-5s lines=%5d group=%-10s ev=%s"
      % (os.path.basename(p), flab, v, len(lines), grp, ev))

w("")
w("文件名标签 vs 内容判读 不一致项：")
bad = [r for r in rows if r[1] in ("HIT", "MISS", "JAM") and r[2] != r[1]]
w("  " + ("; ".join(os.path.basename(r[0]) + "=" + str(r[2]) for r in bad) if bad else "(无)"))

ANALYZE = [(p, v, g) for (p, fl, g), (_, _, v, g2, _, _) in zip(files, rows)
           if v in ("HIT", "MISS", "JAM") and g in ("golden", "golden_dup", "dcshot")]

pre_kv = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
post_kv = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
all_kv = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
feat_kv = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
feat_num = collections.defaultdict(lambda: collections.defaultdict(list))

per_file = []
w("")
w("=" * 110)
w("PRE/POST 切分（分界=第一条 'p0 physical write' 或 'cfi restoring/restore' 行）")
w("=" * 110)
for p, v, g in ANALYZE:
    lines = read(p)
    pre, post = phase_split(lines)
    per_file.append((os.path.basename(p), v, g, pre, post))
    w("%-34s %-5s pre=%5d post=%5d" % (os.path.basename(p), v, len(pre), len(post)))

for name in ("PRE", "POST", "ALL"):
    for fn, v, g, pre, post in per_file:
        seg = {"PRE": pre, "POST": post, "ALL": pre + post}[name]
        tgt = {"PRE": pre_kv, "POST": post_kv, "ALL": all_kv}[name]
        for k, cc in kv(seg, KEYS).items():
            for val, n in cc.items():
                tgt[k][v][val] += n
        if name == "PRE":
            for k, val in feats(pre).items():
                feat_kv[k][v][str(val)] += 1
                if str(val).isdigit():
                    feat_num[k][v].append(int(val))

def dump(title, table):
    w("")
    w("=" * 110)
    w(title)
    w("=" * 110)
    for k in sorted(table):
        for lab in sorted(table[k]):
            cc = table[k][lab]
            items = sorted(cc.items(), key=lambda x: (-x[1], x[0]))
            show = ", ".join("%sx%d" % (a, b) for a, b in items[:14])
            if len(items) > 14:
                show += " ... (+%d)" % (len(items) - 14)
            w("%-16s %-5s n_distinct=%3d  %s" % (k, lab, len(cc), show))

dump("PRE（开火前）key=value 分布", pre_kv)
dump("POST（开火后）key=value 分布", post_kv)
dump("ALL 全量 key=value 分布", all_kv)

w("")
w("=" * 110)
w("分离度扫描（HIT vs MISS；JAM 单列不参与）")
w("=" * 110)
for name, table in (("PRE", pre_kv), ("POST", post_kv), ("ALL", all_kv)):
    w("")
    w("--- %s ---" % name)
    perfect, near, missing = [], [], []
    for k in sorted(table):
        if "HIT" not in table[k] or "MISS" not in table[k]:
            missing.append(k); continue
        sa, sb = set(table[k]["HIT"]), set(table[k]["MISS"])
        inter = sa & sb
        if not inter:
            perfect.append((k, sa, sb))
        else:
            near.append((len(inter), k, sa, sb, inter))
    w("  完全不重叠:")
    for k, sa, sb in perfect:
        w("    %-16s HIT=%s MISS=%s" % (k, sorted(sa), sorted(sb)))
    if not perfect:
        w("    (无)")
    w("  有重叠（按重叠数升序）:")
    for n, k, sa, sb, inter in sorted(near):
        w("    %-16s HIT=%s MISS=%s INTER=%s" % (k, sorted(sa), sorted(sb), sorted(inter)))

w("")
w("=" * 110)
w("PRE 派生特征分布")
w("=" * 110)
for k in feat_kv:
    w("  %s" % k)
    for lab in sorted(feat_kv[k]):
        items = sorted(feat_kv[k][lab].items(), key=lambda x: (-x[1], x[0]))
        w("    %-5s %s" % (lab, ", ".join("%sx%d" % (a, b) for a, b in items[:16]) + (" ..." if len(items) > 16 else "")))

w("")
w("=" * 110)
w("PRE 特征数值范围（min..max, mean）")
w("=" * 110)
for k in feat_num:
    parts = []
    for lab in sorted(feat_num[k]):
        vs = feat_num[k][lab]
        if vs:
            parts.append("%s n=%d min=%d max=%d mean=%.2f" % (lab, len(vs), min(vs), max(vs), sum(vs) / len(vs)))
    if parts:
        w("  %-22s %s" % (k, " | ".join(parts)))

w("")
w("=" * 110)
w("结局四连原文（cfi restore / app fops slide / fops-loop / pipe physrw）")
w("=" * 110)
pat = re.compile(r"cfi misc_fops|cfi restoring|app fops slide attempt|CP main: fops-loop|pipe physrw pid|APP_FOPS_SINGLE_SHOT")
for p, v, g in ANALYZE:
    lines = read(p)
    hits = [ln for ln in lines if pat.search(ln)]
    w("")
    w("### %s [%s]" % (os.path.basename(p), v))
    for ln in hits[:14]:
        w("    " + ln)
    if not hits:
        w("    (无此类行)")

with open(OUT, "w", encoding="utf-8") as f:
    f.write(buf.getvalue())
print("written:", OUT)
