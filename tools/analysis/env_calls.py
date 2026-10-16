# -*- coding: utf-8 -*-
"""扫描 text_disasm.txt：列出所有 getenv / setenv / env_int 调用点及目标字符串。
方法：找到 bl plt getenv/setenv (0x23920/0x23d70) 或 bl env_int(0x22ef4)/atoi 行，
向前回溯最近的把字符串地址放进 x0 的指令（adrp+add / adr / add imm）。
"""
import re, sys

DIS = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\analysis\text_disasm.txt"
STR = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\analysis\strings_rodata.txt"

strings = {}
for line in open(STR, encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    if "\t" not in line:
        continue
    a, _, s = line.partition("\t")
    a = a.strip()
    if a.startswith("0x"):
        try:
            strings[int(a, 16)] = s
        except ValueError:
            pass

lines = open(DIS, encoding="utf-8", errors="replace").read().splitlines()
# 行格式假设: 0x10d90: mov x0, x1   ; ... （若带注释可能不同，先探一行）
# 实际格式由 slice/annotate 决定：'0xADDR:\tmnemonic ...' 与注释 '; "str"'
pat_addr = re.compile(r"^(0x[0-9a-f]+):\s*(.*)$")

# 建立 adrp/adr/add 目标解析：简化——只匹配注释里的 "0x...." 或字符串
TARGETS = {0x23920: "getenv", 0x23d70: "setenv", 0x22ef4: "env_int"}

# 预处理：一遍扫描维护 adrp/adr 后的寄存器页表，遇到 add x0,base,#imm 时解析字符串
pages = {}   # reg -> page addr
last_x0 = None  # (code_addr, str_addr)
x0_hist = []
for line in lines:
    m = pat_addr.match(line)
    if not m:
        continue
    addr = int(m.group(1), 16)
    body = m.group(2).strip()
    ma = re.match(r"adrp\s+(x\d+),\s*#(0x[0-9a-f]+)", body)
    if ma:
        pages[ma.group(1)] = int(ma.group(2), 16)
        continue
    ma = re.match(r"adr\s+(x\d+),\s*#(0x[0-9a-f]+)", body)
    if ma:
        pages[ma.group(1)] = int(ma.group(2), 16)
        if ma.group(1) == "x0":
            a = pages["x0"]
            last_x0 = (addr, a if a in strings else None)
            x0_hist.append(last_x0)
        continue
    ma = re.match(r"add\s+(x0),\s*(x\d+),\s*#(0x[0-9a-f]+)", body)
    if ma and ma.group(2) in pages:
        a = pages[ma.group(2)] + int(ma.group(3), 16)
        last_x0 = (addr, a if a in strings else None)
        x0_hist.append(last_x0)
        continue
    if re.match(r"(mov|orr)\s+x0,", body):
        last_x0 = (addr, None)
        x0_hist.append(last_x0)

out = []
for i, line in enumerate(lines):
    m = pat_addr.match(line)
    if not m:
        continue
    body = m.group(2)
    mb = re.search(r"bl\s+#(0x[0-9a-f]+)", body)
    if not mb:
        mb = re.search(r"bl\s+(\w+)\s*;\s*plt\s+(0x[0-9a-f]+)", body)
        if mb:
            tgt = int(mb.group(2), 16)
            name = mb.group(1)
        else:
            continue
    else:
        tgt = int(mb.group(1), 16)
        name = None
    fn = TARGETS.get(tgt) or (name if name in ("getenv", "setenv") else None)
    if fn is None:
        continue
    addr = int(m.group(1), 16)
    # 找最近一条 addr <= 调用点且距离 <=32 字节的 x0 记录
    best = None
    for (ca, sa) in reversed(x0_hist):
        if ca <= addr and addr - ca <= 32:
            best = (ca, sa)
            break
    sa = best[1] if best else None
    out.append((hex(addr), fn, hex(sa) if sa else "?", repr(strings[sa]) if sa else "?"))

for r in out:
    print("\t".join(r))
