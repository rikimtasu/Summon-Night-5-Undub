# -*- coding: utf-8 -*-
"""Locate the SN5 save subsystem: strings, their consumers, and the crypto.

The save files are strongly encrypted with a per-save keystream (XOR of two
saves stays high-entropy, no repeated 8/16/32-byte blocks, no periodicity,
uniform byte distribution). So there is no statistical shortcut - the only
route is to find the game's own decrypt routine and its key derivation.

Strategy:
  1. find the save-related strings and their fvas
  2. find code that references them (lui/ori pairs, and lui+addiu)
  3. among the referencing functions, look for the read->transform->write shape
     and for tell-tale constants of common PRNGs / block ciphers
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

print('=== save-related strings ===')
hits = []
for m in re.finditer(rb'[ -~]{4,}', d):
    s = m.group()
    sl = s.lower()
    if (b'save' in sl or b'data.bin' in sl or b'encrypt' in sl
            or b'crypt' in sl or b'.bin' == sl[-4:] or b'ms0:' in sl):
        hits.append((m.start(), s))
for off, s in hits:
    print('  0x%06X  %r' % (off, s))

# fvas of the interesting ones
KEY = [s for _, s in hits if any(k in s for k in
       (b'DATA.BIN', b'SAVEDATA', b'comSv', b'ncrypt', b'rypt'))]
print('\n=== key string fvas ===')
key_fvas = []
for off, s in hits:
    if s in KEY:
        key_fvas.append((off, s))
        print('  0x%06X %r' % (off, s))


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


def fn_start(a):
    for back in range(a, max(0, a - 0x400), -4):
        w = struct.unpack('<I', code[back:back + 4])[0]
        if (w >> 16) == 0x27BD and (w & 0x8000):
            return back
    return a


# strings are addressed as lui reg, hi / ori reg, lo  (or addiu)
print('\n=== code references to those string fvas ===')
targets = {o: s for o, s in key_fvas}
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
        if n - li > 6:
            continue
        imm = int(p[2], 0)
        if imm & 0x8000:
            imm -= 0x10000
        full = ((hi << 16) + imm) & 0xFFFFFFFF
        if full in targets:
            refs.append((ins.address, p[0], full, targets[full]))

for addr, reg, full, s in refs:
    print('  0x%06X  %s -> 0x%06X %r   (in fn 0x%06X)'
          % (addr, reg, full, s, fn_start(addr)))
print('\ntotal refs: %d' % len(refs))
print('DONE')
