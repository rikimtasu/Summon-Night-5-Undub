# -*- coding: utf-8 -*-
"""Two threads on the save subsystem.

Thread A - how is the path format string actually reached?
    fva 0x21DCD8 'ms0:/PSP/SAVEDATA/%s%s/%s' has no lui/addiu consumer, which
    leaves two possibilities on MIPS: (1) a pointer-table entry holding the
    fva as a u32, or (2) $gp-relative addressing (addiu/lw off($gp)). Both are
    cheap to test: scan the whole file for the raw u32 0x0021DCD8, and scan the
    code for any $gp-based effective address equal to a wanted fva. To do (2)
    we first need _gp, which the loader sets at program entry.

Thread B - what do the two biggest SavedataRun hubs do?
    All 15 callers cluster at 0x1428AC..0x146B40, immediately before the
    intermission/chapter-select consumer at 0x147418. fn 0x146B40 (4 callers)
    and fn 0x146604 (3 callers) are the largest, so one of them is the
    load/save dialog. Dump both and list every jal, with callee names where we
    already know them, so the buffer's life cycle becomes visible.
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

ANCHORS = {
    0x21DCD8: 'ms0:/PSP/SAVEDATA/%s%s/%s',
    0x213CCA: 'comSvSaveLoad',
    0x21E30C: 's_pLoadGameData is NULL!',
    0x21EA94: 'SAVELOAD_PAC is not read!',
    0x21E760: 'DATA.BIN',
    0x21DCD8: 'ms0:/PSP/SAVEDATA/%s%s/%s',
}

print('=== THREAD A1: raw u32 pointer entries to those fvas ===')
for fva, name in sorted(set(ANCHORS.items())):
    enc = struct.pack('<I', fva)
    s, hits = 0, []
    while True:
        i = d.find(enc, s)
        if i < 0:
            break
        hits.append(i)
        s = i + 1
    print('  0x%06X %-28s -> %d raw pointer(s): %s'
          % (fva, name[:28], len(hits),
             ', '.join('0x%X' % h for h in hits[:6])))

# ---- _gp: look for the entry-point lui/addiu into $gp --------------------
print('\n=== THREAD A2: where is $gp set? (first 0x800 of code) ===')
md0 = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
gp = None
lui_gp = None
for ins in md0.disasm(code[:0x800], 0):
    ops = [x.strip() for x in ins.op_str.split(',')]
    if ins.mnemonic == 'lui' and ops[0] == '$gp':
        lui_gp = int(ops[1], 0)
    elif ins.mnemonic in ('addiu', 'ori') and ops[0] == '$gp' and lui_gp is not None:
        imm = int(ops[2], 0)
        if imm & 0x8000:
            imm -= 0x10000
        gp = ((lui_gp << 16) + imm) & 0xFFFFFFFF
        print('  $gp = lui 0x%X + imm -> 0x%08X' % (lui_gp, gp))
        break
if gp is None:
    print('  no lui/addiu pair into $gp found in first 0x800 '
          '(may be built differently)')

print('\n=== THREAD A3: $gp-relative materialisation of any anchor ===')
if gp is not None:
    found = 0
    for ins in md.disasm(code, 0):
        ops = [x.strip() for x in ins.op_str.split(',')]
        addr = None
        # form 1:  lw/lbu/sw  $r, OFF($gp)
        m = re.search(r'(-?0x[0-9a-fA-F]+|-?\d+)\(\$gp\)', ins.op_str)
        if m:
            imm = int(m.group(1), 0)
            if imm & 0x8000:
                imm -= 0x10000
            addr = (gp + imm) & 0xFFFFFFFF
        # form 2:  addiu/ori  $r, $gp, IMM
        elif len(ops) == 3 and ops[1] == '$gp' and ins.mnemonic in ('addiu', 'ori'):
            imm = int(ops[2], 0)
            if ins.mnemonic == 'addiu' and imm & 0x8000:
                imm -= 0x10000
            addr = (gp + imm) & 0xFFFFFFFF
        if addr in ANCHORS:
            print('  0x%06X %-8s -> 0x%06X %r'
                  % (ins.address, ins.mnemonic, addr, ANCHORS[addr]))
            found += 1
    if not found:
        print('  none')

# ---- THREAD B: the two biggest hubs --------------------------------------
print('\n=== THREAD B: SavedataRun hub bodies ===')
KNOWN = {0x92B0: 'SavedataRun', 0x206C8: 'comSvSaveLoad_reg',
         0x1B2440: 'field_wr_0x669', 0x1B2458: 'field_rd_0x669',
         0x1AD500: 'dbg_log_or_factory', 0x2117DC: 'unknown_2117DC'}


def dump(fn, span=0x300):
    print('\n--- fn 0x%06X (%d bytes shown) ---' % (fn, span))
    jals = []
    for ins in md.disasm(code[fn:fn + span], fn):
        if ins.mnemonic == 'jal':
            t = int(ins.op_str, 0)
            jals.append(t)
            print('  0x%X: jal 0x%X  %s'
                  % (ins.address, t, KNOWN.get(t, '')))
        elif ins.mnemonic in ('lui',) and False:
            pass
    print('    callees: %s' % ', '.join('0x%X' % j for j in sorted(set(jals))))


dump(0x146B40)
dump(0x146604)
print('DONE')
