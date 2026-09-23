# -*- coding: utf-8 -*-
"""Trace the savedata utility wrappers to the real sceUtilitySavedata* stubs.

The EBOOT contains debug wrappers that log the result code:
    'sceUtilitySavedataInitStart() : %08X'
    'sceUtilitySavedataUpdate() : %08X'
    'sceUtilitySavedataShutdownStart() : %08X'
    'SavedataRun'
These are uniquely identifiable, so their consumers are the wrappers around the
PSP savedata API. Inside each wrapper sits the real stub address, and the
CALLERS of those wrappers are the game's save/load routines - which is where
the cipher lives.

Step 1 here: find the wrapper functions. Step 2 is to read them and follow the
jal to the actual kernel stub, so later work has real addresses to xref.
"""
import re
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

# find the strings, convert FILE offset -> fva
want = [b'SavedataRun', b'sceUtilitySavedataInitStart', b'sceUtilitySavedataUpdate',
        b'sceUtilitySavedataShutdownStart', b'SavedataMount', b'SavedataUmount']
found = {}
for m in re.finditer(rb'[ -~]{6,}', d):
    s = m.group()
    for w in want:
        if s.startswith(w):
            found[m.start() - SEG] = s
print('=== anchor strings (fva) ===')
for fva, s in sorted(found.items()):
    print('  0x%06X  %r' % (fva, s))


def fn_start(a):
    for back in range(a, max(0, a - 0x600), -4):
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


# find code that materialises any of these fvas
insns = list(md.disasm(code, 0))
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
        full = ((hi << 16) + imm) & 0xFFFFFFFF
        if full in found:
            refs.append((ins.address, full, found[full]))

print('\n=== consumers of those strings ===')
fns = {}
for a, fva, s in refs:
    st = fn_start(a)
    fns[st] = s
    print('  0x%06X -> str 0x%06X %r  in fn 0x%06X (callers %d)'
          % (a, fva, s[:40], st, len(callers(st))))

print('\n=== the wrapper bodies (to extract the real kernel stubs) ===')
for st in sorted(fns):
    print('\n--- fn 0x%06X  (%s) ---' % (st, fns[st][:44]))
    for ins in md.disasm(code[st:st + 0x180], st):
        ex = '   ; jal 0x%X' % int(ins.op_str, 0) if ins.mnemonic == 'jal' else ''
        print('  0x%X: %-8s %-18s%s' % (ins.address, ins.mnemonic, ins.op_str, ex))
        if ins.mnemonic == 'jr' and ins.op_str.strip() == '$ra':
            nxt = ins.address + 8
            if nxt < st + 0x180:
                w = struct.unpack('<I', code[nxt:nxt + 4])[0]
                if (w >> 16) == 0x27BD and (w & 0x8000):
                    break
print('DONE')
