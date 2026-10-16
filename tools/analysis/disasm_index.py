# -*- coding: utf-8 -*-
"""Build VA<->file mapping, dump rodata strings, disassemble .text with capstone,
and build string xref index (ADRP+ADD/LDR/ADR). Read-only."""
import struct, re, sys, json
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\ghostlock\cve-bin-dc14-sig.extracted"
OUT = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\analysis"

with open(PATH, "rb") as f:
    data = f.read()

(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
shoff_str = e_shoff + e_shstrndx * e_shentsize
_, _, _, _, shstr_off, shstr_size, _, _, _, _ = struct.unpack_from("<IIQQQQIIQQ", data, shoff_str)
shstr = data[shstr_off:shstr_off + shstr_size]
secs = {}
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
        struct.unpack_from("<IIQQQQIIQQ", data, off)
    nm = shstr[sh_name:shstr.find(b"\x00", sh_name)].decode("ascii", "replace")
    secs[nm] = dict(type=sh_type, addr=sh_addr, off=sh_offset, size=sh_size)

def va2off(va):
    for nm in (".text", ".rodata", ".data", ".got", ".plt", ".init_array", ".eh_frame"):
        s = secs.get(nm)
        if s and s["addr"] <= va < s["addr"] + s["size"]:
            return s["off"] + (va - s["addr"])
    # LOAD fallback via program headers
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", data, o)
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None

# ---- strings in .rodata ----
rs = secs[".rodata"]
ro = data[rs["off"]:rs["off"] + rs["size"]]
strings = {}   # va -> text
i = 0
while i < len(ro):
    if 32 <= ro[i] < 127 or ro[i] == 0x1b:
        j = i
        while j < len(ro) and (32 <= ro[j] < 127 or ro[j] == 0x1b):
            j += 1
        if j > i:
            s = ro[i:j].decode("ascii", "replace").replace("\x1b", "\\e")
            if len(s) >= 4:
                strings[rs["addr"] + i] = s
        i = j + 1
    else:
        i += 1

with open(OUT + r"\strings_rodata.txt", "w", encoding="utf-8") as f:
    for va in sorted(strings):
        f.write(f"0x{va:x}\t{strings[va]}\n")

# ---- disassemble .text ----
ts = secs[".text"]
code = data[ts["off"]:ts["off"] + ts["size"]]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
insns = []  # (va, mnemonic, op_str, size)
for ins in md.disasm(code, ts["addr"]):
    insns.append((ins.address, ins.mnemonic, ins.op_str, ins.size))

with open(OUT + r"\text_disasm.txt", "w", encoding="utf-8") as f:
    for va, mn, op, sz in insns:
        f.write(f"0x{va:x}:\t{mn} {op}\n")

# ---- xref index: ADRP/ADR + ADD/LDR immediate combine ----
# register state: track last ADRP/ADR per reg, then ADD reg2 = reg1 + imm
xrefs = {}   # target va -> list of (insn_va, kind)
adrp_state = {}  # reg -> (va, page)
for idx, (va, mn, op, sz) in enumerate(insns):
    if mn == "adrp":
        m = re.match(r"(x\d+|w\d+|sp|xzr), #0x([0-9a-f]+)", op)
        if m:
            adrp_state[m.group(1)] = (va, int(m.group(2), 16))
    elif mn == "adr":
        m = re.match(r"(x\d+|w\d+), #0x([0-9a-f]+)", op)
        if m:
            tgt = int(m.group(2), 16)
            xrefs.setdefault(tgt, []).append((va, "adr"))
    elif mn in ("add",) and "lsl" not in op:
        m = re.match(r"(x\d+|w\d+), (x\d+|w\d+), #0x([0-9a-f]+)$", op)
        if m and m.group(2) in adrp_state:
            srcva, page = adrp_state[m.group(2)]
            tgt = page + int(m.group(3), 16)
            xrefs.setdefault(tgt, []).append((va, "adrp+add"))
            adrp_state[m.group(1)] = (srcva, page)  # propagate
    elif mn in ("ldr", "str") and "#" in op:
        # ldr xt, [xn, #imm] where xn from adrp -> likely string ptr in literal pool; skip
        pass
    elif mn in ("ldr",) :
        # ldr xt, [xn, #imm]? handled below
        m = re.match(r"(x\d+), \[(x\d+), #0x([0-9a-f]+)\]$", op)
        if m and m.group(2) in adrp_state:
            srcva, page = adrp_state[m.group(2)]
            tgt = page + int(m.group(3), 16)
            # only count if target holds a pointer-looking value (data); record anyway
            xrefs.setdefault(tgt, []).append((va, "adrp+ldr"))

# filter to string targets
str_xrefs = {va: refs for va, refs in xrefs.items() if va in strings}
with open(OUT + r"\string_xrefs.txt", "w", encoding="utf-8") as f:
    for va in sorted(str_xrefs):
        f.write(f"0x{va:x}\t{strings[va][:150]}\n")
        for ref, kind in str_xrefs[va]:
            f.write(f"    <- 0x{ref:x} ({kind})\n")

print("strings:", len(strings))
print("text insns:", len(insns))
print("string xrefs:", len(str_xrefs))
