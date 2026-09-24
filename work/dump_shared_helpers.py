# -*- coding: utf-8 -*-
"""Dump the remaining shared save-path helpers, to identify what they do.

The candidate ranking found no XOR anywhere in the save path, but it only
classified functions by XOR presence. A byte-substitution cipher (S-box table
lookup, add/rotate) has NO xor - so the loops still have to be read by eye.

Helpers shared by SaveLoadGame / SaveLoadSystem / SaveLoadSuspend:
    0x0092B0  91 insns, 1 back-edge   savedata state machine (already dumped)
    0x0141610 10 insns                trivial accessor?
    0x0141690 26 insns                ?
    0x016EB28 183 insns, 12 back      184 callers -> memory/string op
    0x016ECD4 76 insns, 5 back        27 callers  -> ?  <priority: it loops>
    0x01A7964 18 insns, 408 callers   trivial, shared
    0x01AD500 469 insns, 750 callers  printf/logger

Priority is 0x16ECD4 (it loops and is save-specific-ish), then the two 0x1416xx
accessors and 0x1A7964, since those are the pieces of the pipeline not yet
understood. For each: full disassembly, jal targets with call counts, and any
indexed table reads (lw/lb from a non-sp/gp base) which would reveal an S-box.
"""
import array
import struct
import bisect
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

words = array.array('I')
words.frombytes(code[:len(code) // 4 * 4])
PRO = sorted(i * 4 for i, x in enumerate(words)
             if (x >> 16) == 0x27BD and (x & 0x8000))


def extent(a):
    i = bisect.bisect_right(PRO, a + 8)
    return PRO[i] if i < len(PRO) else len(code)


def callers(t):
    enc = struct.pack('<I', 0x0C000000 | (t >> 2))
    out, s = [], 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


TARGETS = [0x141690, 0x141610, 0x1A7964, 0x16ECD4, 0x16EB28]

for t in TARGETS:
    print('\n' + '=' * 72)
    print('=== 0x%06X  callers=%d  ===' % (t, len(callers(t))))
    print('=' * 72)
    insns = list(md.disasm(code[t:extent(t)], t))
    if len(insns) > 200:
        insns = insns[:200]
        truncated = True
    else:
        truncated = False
    for i in insns:
        mark = ''
        if i.mnemonic == 'jal':
            ct = int(i.op_str, 0)
            mark = '  ; jal 0x%X (%d c)' % (ct, len(callers(ct)))
        elif i.mnemonic in ('xor', 'xori', 'rotr', 'rotl', 'wsbh'):
            mark = '  ; <XOR/ROT>'
        elif i.mnemonic in ('mult', 'multu', 'div', 'divu'):
            mark = '  ; <MUL/DIV>'
        print('0x%X: %-8s %-24s%s' % (i.address, i.mnemonic, i.op_str, mark))
    if truncated:
        print('  ... truncated at 200 insns')
print('DONE')
