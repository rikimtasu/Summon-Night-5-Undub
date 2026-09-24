# -*- coding: utf-8 -*-
"""Dump the two tables the save-slot description builder indexes.

    0x23311C  stride 8  { ptr "Ch. N, ", ptr <title> }   indexed by id 20 (chapter)
    0x2331B4  stride 4  ptr                              indexed by id 50 when the
                                                          value is bucketed < 40
fva -> file offset is +SEG (0xC0).
"""
import os
import struct

_HERE = os.path.dirname(os.path.abspath(__file__))
BOOT = os.path.join(os.path.dirname(_HERE), 'EBOOT_USA_decrypted.bin')
SEG = 0xC0
STR_LO, STR_HI = 0x210000, 0x246000


def s(d, w):
    if not (STR_LO <= w < STR_HI):
        return None
    fo = w + SEG
    end = d.find(b'\x00', fo)
    if end < 0 or not 0 < end - fo <= 80:
        return None
    raw = d[fo:end]
    if not all(0x20 <= c < 0x7F for c in raw):
        return '<%d non-ascii bytes>' % len(raw)
    return raw.decode('latin-1')


def main():
    d = open(BOOT, 'rb').read()

    print('=' * 72)
    print('0x23311C  stride 8   { "Ch. N, ", <title> }   indexed by id 20')
    print('=' * 72)
    for i in range(34):
        a, b = struct.unpack_from('<II', d, 0x23311C + i * 8 + SEG)
        sa, sb = s(d, a), s(d, b)
        print('  [%2d]  %-18s  %s' % (i, repr(sa), repr(sb)))

    print()
    print('=' * 72)
    print('0x2331B4  stride 4   ptr   indexed by id 50 (value bucketed < 40)')
    print('=' * 72)
    for i in range(28):
        w = struct.unpack_from('<I', d, 0x2331B4 + i * 4 + SEG)[0]
        print('  [%2d]  0x%08X  %s' % (i, w, repr(s(d, w))))
    print('DONE')


if __name__ == '__main__':
    main()
