# -*- coding: utf-8 -*-
"""Trace the rScene / SceneDecode strings to the script-block loader.

Both are vaddr 0x2128C4 and 0x2130DB (file offset - 0xC0). Find the code that
materializes them, then disassemble the referencing function: it should be the
story-block loader/decompressor whose argument is a scene or entry id.
"""
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

SEG = 0xC0
d = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False
insns = list(md.disasm(code, 0))

TARGETS = {0x2128C4: 'rScene', 0x2130DB: 'SceneDecode'}
recent = []
hits = []
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'lui':
        r, v = ins.op_str.split(',')
        recent.append((idx, ins.address, int(v.strip(), 0)))
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
        for (li, la, hi) in recent:
            if idx - li > 8:
                continue
            full = ((hi << 16) + imm) & 0xFFFFFFFF
            if full in TARGETS:
                hits.append((TARGETS[full], la, ins.address))

print('=== xrefs ===')
for h in hits:
    print('  %-12s lui@0x%X use@0x%X' % h)

for name, la, ua in hits:
    start = ua
    for back in range(ua, max(0, ua - 0x300), -4):
        w = struct.unpack('<I', code[back:back + 4])[0]
        if (w >> 16) == 0x27BD and (w & 0x8000):
            start = back
            break
    print('\n--- function ~0x%X referencing %s ---' % (start, name))
    for ins in md.disasm(code[start:start + 0x220], start):
        ex = ''
        if ins.mnemonic == 'jal':
            ex = '   ; jal 0x%X' % int(ins.op_str, 0)
        mark = '  <<< %s' % name if ins.address in (la, ua) else ''
        print('   0x%X: %s %s%s%s' % (ins.address, ins.mnemonic, ins.op_str, ex, mark))
print('DONE', flush=True)
