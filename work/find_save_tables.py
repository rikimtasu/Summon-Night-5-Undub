# -*- coding: utf-8 -*-
"""Find the string-pointer tables that reference the SN5 save strings.

Direct lui/ori scanning found ZERO references to 'DATA.BIN',
'ms0:/PSP/SAVEDATA/%s%s/%s' and 'comSvSaveLoad', even though those strings are
clearly used. So they are reached through a table of 32-bit pointers (the
classic .rodata descriptor pattern already seen elsewhere in this EBOOT).

Method: treat every 4-aligned word in the file as a candidate pointer; if it
equals a known string fva, we have a table entry. Then find code that loads
the TABLE's address, and walk up to the function that uses it.
"""
import struct
import re
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

NAMES = {
    0x213D8A - SEG: 'comSvSaveLoad',
    0x21DD98 - SEG: 'ms0:/PSP/SAVEDATA/%s%s/%s',
    0x21E820 - SEG: 'DATA.BIN',
    0x21E374 - SEG: 'src:SaveLoad.cpp (unix)',
    0x21EAFC - SEG: 'src:SaveLoad.cpp (win)',
    0x21EB54 - SEG: 'SAVELOAD_PAC is not read!',
    0x21E028 - SEG: 'Save Data',
    0x21AB5D - SEG: 'comSvSaveLoad()',
    0x212468 - SEG: 'SavedataRun',
    0x21DC38 - SEG: 'ms0:/PSP/GAME/ULUS10656/',
    0x21AB0B - SEG: 'comSvSaveLoad() 2',
    0x21EDAB - SEG: 'SaveLoadGame',
    0x21EE0B - SEG: 'SaveLoadSystem',
    0x21EE1A - SEG: 'SaveLoadSuspend',
}

# NOTE: the string regex above reports RAW FILE offsets, but every address the
# code and the .rodata pointer tables use is a FILE VADDR = file_offset - SEG.
# Mixing the two made an early version of this script "find" a pointer to
# 0x21E028 that actually pointed 0xC0 bytes past the string.

print('=== scanning for 32-bit pointers to those fvas ===')
found = {}
for off in range(0, len(d) - 4, 4):
    w = struct.unpack_from('<I', d, off)[0]
    if w in NAMES:
        found[off] = (w, NAMES[w])
        print('  ptr at file 0x%06X -> 0x%06X  %s' % (off, w, NAMES[w]))

# group into tables (consecutive or near-consecutive entries)
print('\n=== grouping into tables ===')
addrs = sorted(found)
tables = []
cur = [addrs[0]] if addrs else []
for a in addrs[1:]:
    if a - cur[-1] <= 0x40:
        cur.append(a)
    else:
        tables.append(cur)
        cur = [a]
if cur:
    tables.append(cur)
for t in tables:
    print('  table at 0x%06X..0x%06X : %d known entries' % (t[0], t[-1], len(t)))

# Dump the neighbourhood of every hit as POINTERS (subtract SEG from each word
# before treating it as a string address: the words in .rodata hold FILE vaddrs
# only after the SEG offset is removed - the ELF base is what makes them run).
print('\n=== neighbourhood as string pointers (word is already a fva) ===')
for off in addrs:
    print('  --- around file 0x%06X ---' % off)
    for o in range(off - 0x18, off + 0x30, 4):
        if not (0 <= o < len(d) - 4):
            continue
        w = struct.unpack_from('<I', d, o)[0]
        tag = ''
        if 0x210000 <= w <= 0x230000:
            s = d[w + SEG:w + SEG + 44].split(b'\x00')[0]
            if s and all(32 <= c < 127 or c > 160 for c in s):
                tag = '  -> %r' % s
        print('    0x%06X: 0x%08X%s' % (o, w, tag))


def fn_start(a):
    for back in range(a, max(0, a - 0x400), -4):
        w = struct.unpack('<I', code[back:back + 4])[0]
        if (w >> 16) == 0x27BD and (w & 0x8000):
            return back
    return a


def callers(t):
    enc = struct.pack('<I', 0x0C000000 | (t >> 2))
    out = []
    s = 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


# For each table, find code referencing the table base, then its function
print('\n=== functions that reference those tables ===')
insns = list(md.disasm(code, 0))
for t in tables:
    for base in (t[0],):
        # find lui/addiu pairs producing `base`
        lui_at = {}
        refs = []
        for n, ins in enumerate(insns):
            if ins.mnemonic == 'lui':
                r, v = [x.strip() for x in ins.op_str.split(',')]
                lui_at[r] = (n, int(v, 0))
            elif ins.mnemonic in ('ori', 'addiu'):
                p = [x.strip() for x in ins.op_str.split(',')]
                if len(p) != 3 or p[1] not in lui_at:
                    continue
                li, hi = lui_at[p[1]]
                if n - li > 8:
                    continue
                imm = int(p[2], 0)
                if imm & 0x8000:
                    imm -= 0x10000
                if (((hi << 16) + imm) & 0xFFFFFFFF) == base:
                    refs.append(ins.address)
        fns = sorted({fn_start(a) for a in refs})
        print('  table 0x%06X: %d code refs, functions %s'
              % (base, len(refs), ['0x%X' % f for f in fns]))
        for f in fns:
            cs = callers(f)
            print('      fn 0x%06X  callers=%d %s'
                  % (f, len(cs), [hex(c) for c in cs[:6]]))
print('DONE')
