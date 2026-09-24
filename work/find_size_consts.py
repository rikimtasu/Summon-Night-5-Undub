# -*- coding: utf-8 -*-
"""Anchor on the exact save sizes instead of NID names.

The import table turned out to be a dense NID array with no stub pointers, and
naming the entries I care about (sceIoRead, sceUtilitySavedata*) needs a name
table this EBOOT does not carry. Rather than keep identifying imports, use a
constant only the save code can contain:

    GAME DATA.BIN   = 170144 = 0x298A0
    SYSTEM DATA.BIN  =  22752 = 0x58E0

Both are >16 bits for 0x298A0, so MIPS must build it with lui+ori (or lui+addiu)
or, if it is a static const, store it as a raw u32. Three probes:

  A. raw u32 0x000298A0 / 0x000058E0 anywhere in the file (a size table entry)
  B. lui/ori (and lui/addiu) pairs whose result equals 0x298A0 or 0x58E0
  C. any ori/addiu with immediate 0x98A0 (the low half) - catches the pair even
     if the lui uses a different register or sits further away

For every hit, print the enclosing function and its caller count. The function
that sizes the buffer is the file I/O function; the transform is adjacent.
"""
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

TARGETS = {0x298A0: 'GAME DATA.BIN 170144',
           0x58E0: 'SYSTEM DATA.BIN 22752'}


def fn_start(a, back=0x800):
    for t in range(a, max(0, a - back), -4):
        w = struct.unpack_from('<I', code, t)[0]
        if (w >> 16) == 0x27BD and (w & 0x8000):
            return t
    return a


def callers(target):
    enc = struct.pack('<I', 0x0C000000 | (target >> 2))
    out, s = [], 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


print('=== A. raw u32 size constants in the file ===')
for val, name in TARGETS.items():
    enc = struct.pack('<I', val)
    s, locs = 0, []
    while True:
        i = d.find(enc, s)
        if i < 0:
            break
        locs.append(i)
        s = i + 1
    print('  0x%05X %-22s -> %d : %s'
          % (val, name, len(locs), ', '.join('0x%X' % l for l in locs[:8])))

print('\n=== B/C. code that materialises those sizes ===')
insns = list(md.disasm(code, 0))
results = {}
for n, ins in enumerate(insns):
    if ins.mnemonic not in ('ori', 'addiu'):
        continue
    ops = [x.strip() for x in ins.op_str.split(',')]
    if len(ops) != 3:
        continue
    try:
        imm = int(ops[2], 0)
    except ValueError:
        continue
    signed = imm - 0x10000 if (imm & 0x8000) else imm

    # exact 16-bit immediate match (0x58E0 directly, or 0x98A0 low half)
    matched = None
    if imm in (0x58E0, 0x98A0):
        matched = imm
    if matched is None:
        continue

    # resolve a lui for the same register within 8 instrs -> full value
    full = None
    for k in range(max(0, n - 8), n):
        li = insns[k]
        if li.mnemonic != 'lui':
            continue
        lo = [x.strip() for x in li.op_str.split(',')]
        if lo[0] != ops[1]:
            continue
        hi = int(lo[1], 0)
        add = signed if ins.mnemonic == 'addiu' else imm
        cand = ((hi << 16) + add) & 0xFFFFFFFF
        if cand in TARGETS:
            full = cand
            break
    # also: ori $r,$zero,imm is a complete 16-bit value by itself
    if full is None and imm in TARGETS and ops[2] != str(hex(imm)):
        pass
    if full is None and imm in TARGETS:
        full = imm
    if full is None:
        continue

    st = fn_start(ins.address)
    results.setdefault(st, []).append((ins.address, full))
    print('  0x%06X %-6s -> 0x%05X %-22s [fn 0x%06X callers=%d]'
          % (ins.address, ins.mnemonic, full, TARGETS[full],
             st, len(callers(st))))

print('\n=== distinct enclosing functions ===')
for st in sorted(results):
    print('  fn 0x%06X  callers=%d  sizes=%s'
          % (st, len(callers(st)),
             sorted({hex(v) for _, v in results[st]})))
print('DONE')
