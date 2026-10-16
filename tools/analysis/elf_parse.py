# -*- coding: utf-8 -*-
"""ELF header/section/segment parser for cve-bin-dc14-sig.extracted (read-only)."""
import struct, sys

PATH = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\ghostlock\cve-bin-dc14-sig.extracted"

def main():
    with open(PATH, "rb") as f:
        data = f.read()
    print("size =", len(data))
    print("magic =", data[:16].hex())
    assert data[:4] == b"\x7fELF", "not ELF"
    ei_class = data[4]  # 1=32, 2=64
    ei_data = data[5]   # 1=LE, 2=BE
    print("class =", {1: "ELF32", 2: "ELF64"}.get(ei_class), "data =", {1: "LE", 2: "BE"}.get(ei_data))
    print("OSABI =", data[7], "type =", struct.unpack_from("<H", data, 16)[0],
          "machine =", struct.unpack_from("<H", data, 18)[0])  # 183 = EM_AARCH64
    # ELF64 header
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHIQQQIHHHHHH", data, 16)
    print(f"entry=0x{e_entry:x} phoff=0x{e_phoff:x} shoff=0x{e_shoff:x} flags=0x{e_flags:x}")
    print(f"phentsize={e_phentsize} phnum={e_phnum} shentsize={e_shentsize} shnum={e_shnum} shstrndx={e_shstrndx}")

    # program headers
    print("\n== Program Headers ==")
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", data, off)
        tname = {1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 0x6474e550: "GNU_EH_FRAME",
                 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO"}.get(p_type, hex(p_type))
        prot = ("R" if p_flags & 4 else "-") + ("W" if p_flags & 2 else "-") + ("X" if p_flags & 1 else "-")
        print(f"  [{i}] {tname:14s} {prot} off=0x{p_offset:06x} vaddr=0x{p_vaddr:012x} filesz=0x{p_filesz:06x} memsz=0x{p_memsz:06x}")

    # section headers
    print("\n== Sections ==")
    if e_shoff and e_shnum:
        shoff_str = e_shoff + e_shstrndx * e_shentsize
        shstr_sh = struct.unpack_from("<IIQQQQIIQQ", data, shoff_str)
        shstr_off = shstr_sh[4]  # sh_offset
        shstr_size = shstr_sh[5]
        shstr = data[shstr_off:shstr_off + shstr_size]
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
                struct.unpack_from("<IIQQQQIIQQ", data, off)
            nm = shstr[sh_name:shstr.find(b"\x00", sh_name)].decode("ascii", "replace")
            tname = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 8: "NOBITS",
                     9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 6: "DYNAMIC",
                     7: "NOTE", 0x6ffffff6: "GNU_HASH", 0x6fffffff: "VERNEED", 0x6ffffffe: "VERNEEDNUM",
                     0x6ffffffd: "VERSYM"}.get(sh_type, hex(sh_type))
            print(f"  [{i:2d}] {nm:20s} {tname:10s} addr=0x{sh_addr:012x} off=0x{sh_offset:06x} size=0x{sh_size:06x} link={sh_link} info={sh_info} entsize={sh_entsize}")

if __name__ == "__main__":
    main()
