import struct, sys

SRC = r'D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\patchwork\device_binary'
DST = r'D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\patchwork\device_binary_patched'

data = bytearray(open(SRC, 'rb').read())

# ---- 解析 ELF64 program headers，建立 vaddr -> file offset ----
assert data[:4] == b'\x7fELF', 'not ELF'
e_phoff = struct.unpack('<Q', data[0x20:0x28])[0]
e_phentsize = struct.unpack('<H', data[0x36:0x38])[0]
e_phnum = struct.unpack('<H', data[0x38:0x3a])[0]

segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack('<I', data[off:off+4])[0]
    if p_type != 1:  # PT_LOAD
        continue
    p_offset = struct.unpack('<Q', data[off+8:off+16])[0]
    p_vaddr  = struct.unpack('<Q', data[off+16:off+24])[0]
    p_filesz = struct.unpack('<Q', data[off+32:off+40])[0]
    segs.append((p_vaddr, p_offset, p_filesz))

def v2o(vaddr):
    for p_vaddr, p_offset, p_filesz in segs:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    raise ValueError('vaddr not mapped: 0x%x' % vaddr)

def read32(vaddr):
    o = v2o(vaddr)
    return struct.unpack('<I', data[o:o+4])[0], o

def decode_cbnz(instr):
    # CBNZ (32-bit): 0011010 1 imm19 Rt
    op = (instr >> 24) & 0xFF
    if (instr & 0x7F000000) != 0x35000000:
        return None
    imm19 = (instr >> 5) & 0x7FFFF
    rt = instr & 0x1F
    if imm19 & (1 << 18):
        imm19 -= (1 << 19)
    return imm19 * 4, rt

def decode_bcond(instr, pc):
    # B.cond: 0101010 0 imm19 0 cond
    if (instr & 0xFF000010) != 0x54000000:
        return None
    imm19 = (instr >> 5) & 0x7FFFF
    if imm19 & (1 << 18):
        imm19 -= (1 << 19)
    cond = instr & 0xF
    return pc + imm19 * 4, cond

# ---- 检查目标指令 0x22b50: cbnz w8, #0x22c74 ----
vaddr = 0x22b50
instr, foff = read32(vaddr)
print('0x%x 文件偏移 0x%x 指令 0x%08X' % (vaddr, foff, instr))
dec = decode_cbnz(instr)
print('  解码 CBNZ: 目标=0x%x Rt=w%d' % (vaddr + dec[0], dec[1]) if dec else '  不是 CBNZ!')
assert dec is not None, 'mismatch'

# ---- 补丁: NOP 掉 cbnz -> 护栏 1 不再触发（允许 clean-miss 重试）----
NOP = 0xD503201F
data[foff:foff+4] = struct.pack('<I', NOP)
print('已写入 NOP @ 偏移 0x%x' % foff)

# ---- 复核 ----
instr2, _ = read32(vaddr)
print('复核: 0x%08X %s' % (instr2, 'NOP ✓' if instr2 == NOP else 'FAIL'))

# ---- 顺便打印其余两个护栏（仅确认，不改）----
for va, name in [(0x22b6c, 'flag2 fresh-P0-session'), (0x22b84, 'flag3 p0-oracle-dirtied'), (0x22c28, 'prctl-errpath'), (0x22c88, 'getppid-check')]:
    i, o = read32(va)
    d = decode_cbnz(i)
    b = decode_bcond(i, va)
    if d:
        print('%s @0x%x: 0x%08X cbnz w%d, #0x%x' % (name, va, i, d[1], va + d[0]))
    elif b:
        print('%s @0x%x: 0x%08X b.cond(%d) -> #0x%x' % (name, va, i, b[1], b[0]))
    else:
        print('%s @0x%x: 0x%08X (其他)' % (name, va, i))

open(DST, 'wb').write(bytes(data))
print('\n已输出: %s' % DST)
