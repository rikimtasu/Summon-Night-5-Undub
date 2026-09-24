# -*- coding: utf-8 -*-
"""Locate the story-block header magic as DATA in the EBOOT, then its xrefs.

hdr_magic_scan.py found ZERO immediate materializations of 0x10000201 / 0x10000002
in the USA EBOOT code, yet the block header appears verbatim in RAM.  So the
header is not built with lui/ori/addiu - it must be copied from a constant pool
(lw from .rodata, then sw into the block).

This finds the magic as *data* in both EBOOTs, and for every hit reports the fva
so it can be fed to scan_addr.py for code xrefs.  Hitting the loader this way is
what would let us expand 02.DAT offline and enumerate every chapter without
booting the game per chapter.

Run:  python find_block_magic_data.py
"""
import os
import struct
import sys

WORK = r'D:\Documents\Default Project\work'
SEG = 0xC0
TARGETS = {
    'pair 0x10000201+0x10000002': struct.pack('<II', 0x10000201, 0x10000002),
    'dword 0x10000201': struct.pack('<I', 0x10000201),
    'dword 0x10000002': struct.pack('<I', 0x10000002),
    'container 0x10040101': struct.pack('<I', 0x10040101),
    'container 0x10000001': struct.pack('<I', 0x10000001),
}
EBOOTS = [
    ('usa', os.path.join(os.path.dirname(WORK), 'EBOOT_USA_decrypted.bin')),
    ('jp', os.path.join(os.path.dirname(WORK), 'EBOOT_JP_decrypted.bin')),
]


def find_all(hay, needle, limit=40):
    out, start = [], 0
    while len(out) < limit:
        o = hay.find(needle, start)
        if o < 0:
            break
        out.append(o)
        start = o + 1
    return out


def main():
    found_any = False
    for tag, path in EBOOTS:
        if not os.path.isfile(path):
            print('%s: MISSING %s' % (tag, path))
            continue
        data = open(path, 'rb').read()
        print('=== %s EBOOT (%d bytes) ===' % (tag, len(data)))
        for name, pat in TARGETS.items():
            hits = find_all(data, pat)
            fvas = ['0x%X' % (h - SEG) for h in hits if h >= SEG]
            print('  %-28s %d hit(s)  fva: %s'
                  % (name, len(hits), ', '.join(fvas) if fvas else '-'))
            if fvas:
                found_any = True
        print()

    if found_any:
        print('Next: for each fva above, run  python scan_addr.py <fva>')
        print('to find the code that loads it - that is the script loader.')
    else:
        print('No header magic as data either: the block is assembled by code')
        print('that builds the words with shifts/or - widen the immediate scan')
        print('to include shift/or sequences before assuming a data copy.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
