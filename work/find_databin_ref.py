# -*- coding: utf-8 -*-
"""Find how 'DATA.BIN' is referenced, given it is NOT in a pointer table.

The pointer-table scan finds Save/Clear/Intermission Data but no pointer to
'DATA.BIN'. Two likely explanations:
  (a) it is built on the stack at runtime (snprintf of a base + "DATA.BIN"), or
  (b) it is passed to sceIoOpen from a fixed .rodata address loaded with a
      lui/addiu pair whose low half is the *runtime* address.

So search two ways:
  1. any lui/addiu/ori pair in code that materialises 0x21E760 (the fva of
     DATA.BIN) - already tried, zero hits, so also try the RUNTIME address
     0x08804000+0x21E760 in case the constant was pre-relocated.
  2. all lui/addiu pairs that materialise ANY address inside the 0x21E700..
     0x21E900 window, to catch a neighbouring constant.
Also dump the disassembly of the function that owns the sceIoOpen call found
earlier for the 02.DAT loader (0x1ABFF0) - the save path may share it.
"""
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
RT = 0x08804000
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

DATABIN_FVA = 0x21E820 - SEG
SAVEDIR_FVA = 0x21DD98 - SEG
SAVELOAD_FVA = 0x213D8A - SEG
print('DATA.BIN fva=0x%06X  SAVEDATA fva=0x%06X  comSvSaveLoad fva=0x%06X'
      % (DATABIN_FVA, SAVEDIR_FVA, SAVELOAD_FVA))

WANT = {
    DATABIN_FVA: 'DATA.BIN fva',
    RT + DATABIN_FVA: 'DATA.BIN runtime',
    SAVEDIR_FVA: 'SAVEDATA fva',
    RT + SAVEDIR_FVA: 'SAVEDATA runtime',
    SAVELOAD_FVA: 'comSvSaveLoad fva',
    RT + SAVELOAD_FVA: 'comSvSaveLoad runtime',
}

insns = list(md.disasm(code, 0))
lui_at = {}
hits = []
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
        if full in WANT:
            hits.append((ins.address, p[0], full, WANT[full]))

print('\n=== direct code references ===')
for a, reg, full, what in hits:
    print('  0x%06X  %s = 0x%08X  (%s)' % (a, reg, full, what))
if not hits:
    print('  NONE')

# window scan: any constant in 0x21E700..0x21E900
print('\n=== any code constant landing in 0x21E700..0x21E900 ===')
lui_at = {}
win = []
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
        if 0x21E700 <= full <= 0x21E900:
            s = d[full + SEG:full + SEG + 40].split(b'\x00')[0]
            win.append((ins.address, full, s))
for a, f, s in win:
    print('  0x%06X -> 0x%06X  %r' % (a, f, s))
if not win:
    print('  NONE')
print('DONE')
