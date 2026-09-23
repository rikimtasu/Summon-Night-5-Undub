"""Locate the EBOOT cheat/debug menu and any chapter-jump action.

USA EBOOT carries strings the JP build lacks: 'Debugging.', 'Cheat: Mission',
'Cheat: Rematch', 'Cheat: Fabrication', 'Cheat: Save corruption', 'OnChapterFlag',
'CHAPTER'. Strings are at file offsets; vaddr = file offset - 0xC0, and code
builds them with lui/ori or lui/addiu. Find every materialization of those
vaddrs, then disassemble the referencing functions.
"""
import struct
import sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

ROOT = r'D:\Documents\Default Project'
SEG = 0xC0

STRINGS = {
    'Debugging.': 0x21D360,
    'Cheat: Save corruption': 0x21D418,
    'Cheat: Fabrication': 0x21D430,
    'Cheat: Rematch': 0x21D444,
    'Cheat: Mission': 0x21D454,
    'CHAPTER': 0x21E057,
    'OnChapterFlag': 0x214F10,
    'View unlocked illustrations, music, night': 0x21694C,
    'Skip': 0x21C650,
    'chapter error!': 0x215410,
}

d = open(ROOT + r'\EBOOT_USA_decrypted.bin', 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False
insns = list(md.disasm(code, 0))
print('insns:', len(insns))

targets = {}
for name, foff in STRINGS.items():
    v = foff - SEG
    targets[v] = name

# scan lui/ori/addiu pairs (window 8) for exact vaddr matches
recent = []
hits = []
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'lui':
        r, v = ins.op_str.split(',')
        recent.append((idx, ins.address, r.strip(), int(v.strip(), 0)))
        if len(recent) > 14:
            recent.pop(0)
        continue
    if ins.mnemonic in ('ori', 'addiu'):
        p = [x.strip() for x in ins.op_str.split(',')]
        if len(p) != 3:
            continue
        try:
            imm = int(p[2], 0)
        except ValueError:
            continue
        if imm & 0x8000:
            imm -= 0x10000
        for (li, la, r, hi) in recent:
            if idx - li > 8:
                continue
            full = ((hi << 16) + imm) & 0xFFFFFFFF
            if full in targets:
                hits.append((targets[full], la, ins.address, p[0], ins.mnemonic))

print('\n=== string xrefs (file-vaddr = fileoff-0xC0) ===')
for name, lui_a, use_a, dst, mn in hits:
    print('  %-38s lui@0x%-7X use@0x%-7X %s %s' % (name, lui_a, use_a, mn, dst))
if not hits:
    print('  none found via lui+imm; trying absolute u32 pointers in data...')
    for name, foff in STRINGS.items():
        v = foff - SEG
        needle = struct.pack('<I', v)
        s = 0
        while True:
            i = d.find(needle, s)
            if i < 0:
                break
            print('  %-38s u32 ptr at file 0x%X' % (name, i))
            s = i + 1

# disassemble around each hit's function (walk back to a prologue-ish pattern)
seen_funcs = set()
for name, lui_a, use_a, dst, mn in hits:
    # crude function start: scan back for 'addiu $sp, $sp, -N'
    start = use_a
    for back in range(use_a, max(0, use_a - 0x200), -4):
        w = struct.unpack('<I', code[back:back + 4])[0]
        if (w >> 16) == 0x27BD and (w & 0x8000):   # addiu sp,sp,-imm
            start = back
            break
    if start in seen_funcs:
        continue
    seen_funcs.add(start)
    print('\n--- function near 0x%X (ref: %s) ---' % (start, name))
    for ins in md.disasm(code[start:start + 0x180], start):
        mark = '  <<< %s' % name if ins.address in (lui_a, use_a) else ''
        extra = ''
        if ins.mnemonic == 'jal':
            extra = '   ; jal 0x%X' % int(ins.op_str, 0)
        print('   0x%X: %s %s%s%s' % (ins.address, ins.mnemonic, ins.op_str, extra, mark))
print('DONE', flush=True)
