# -*- coding: utf-8 -*-
"""Locate the debug-menu record that prints money, to find the money field.

The EBOOT carries a menu table whose rows are inline fixed-size records:

    u32 type | u32 | u32 | u32(float) | char label[?]
    04 00 00 00 00 00 00 00 7f 96 18 4b 00 00 7a 44 | "  Money    [ %7d ]"
    04 00 00 00 00 00 00 00 7f 96 18 4b 00 00 80 3f | "  Medal    [ %7d ]"

The label is inline, so there is no string pointer to xref - scan_addr.py on
the string finds nothing.  Instead compute the record start (16 bytes before
the label) and look for a lui/addiu materialisation of that address, which is
how the table base reaches the drawing code.
"""
import os
import struct
import sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

_HERE = os.path.dirname(os.path.abspath(__file__))
BOOT = os.path.join(os.path.dirname(_HERE), 'EBOOT_USA_decrypted.bin')
SEG = 0xC0
CODE_END = 0x21121C
HDR = 16


def imm(tok):
    v = int(tok, 0)
    if tok.startswith('-'):
        return v
    return v - 0x10000 if v >= 0x8000 else v


def main():
    d = open(BOOT, 'rb').read()
    for label in (b'  Money    [ %7d ]', b'  Medal    [ %7d ]',
                  b'[ Game               ]'):
        i = d.find(label)
        if i < 0:
            print('label not found: %r' % label)
            continue
        rec = i - HDR
        fva = rec - SEG
        print('=' * 72)
        print('label  %r' % label.decode('latin-1'))
        print('label file off 0x%X   record file off 0x%X   record fva 0x%X'
              % (i, rec, fva))
        print('record bytes: %s' % d[rec:i + 24].hex(' '))
        # every aligned u32 in the file equal to the record fva
        tgt = struct.pack('<I', fva)
        hits = []
        p = 0
        while True:
            p = d.find(tgt, p)
            if p < 0:
                break
            if p % 4 == 0:
                hits.append(p)
            p += 1
        print('aligned pointer(s) to record fva at file off: %s'
              % (['0x%X' % h for h in hits] or 'NONE'))

    # resolve lui/addiu pairs over the whole code section that build an address
    # inside the menu table region, so we find the table base even unaligned
    print('=' * 72)
    print('code sites materialising an address in 0x231F00..0x232600')
    print('=' * 72)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    pend = {}
    found = []
    for ins in md.disasm(d[SEG:SEG + CODE_END], 0):
        toks = [t.strip() for t in ins.op_str.split(',')]
        if ins.mnemonic == 'lui' and len(toks) == 2:
            pend[toks[0]] = int(toks[1], 0) << 16
        elif ins.mnemonic in ('addiu', 'ori') and len(toks) == 3:
            dst, src = toks[0], toks[1]
            if src in pend:
                v = ((pend[src] + imm(toks[2])) & 0xFFFFFFFF
                     if ins.mnemonic == 'addiu'
                     else pend[src] | (int(toks[2], 0) & 0xFFFF))
                pend[dst] = v
                if dst != src:
                    pend.pop(src, None)
                if 0x231F00 <= v <= 0x232600:
                    found.append((ins.address, dst, v))
            else:
                pend.pop(dst, None)
    for a, r, v in found[:40]:
        print('  %08X  %s = 0x%08X' % (a, r, v))
    print('(%d sites)' % len(found))
    print('DONE')
    return 0


if __name__ == '__main__':
    sys.exit(main())
