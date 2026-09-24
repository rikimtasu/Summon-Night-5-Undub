# -*- coding: utf-8 -*-
"""Map the plaintext SN5 save layout now that EncryptSave=False gives it to us.

Confirmed decrypted:
    ULUS10656SN5GAME45  170128 = 0x29890  entropy 0.360  chi2z +1.79e6
    NPJH50696SN5GAME06  170128 = 0x29890  entropy 0.324  chi2z +1.80e6
vs the encrypted baseline at 170144 = 0x29890 + 16 (PPSSPP's 16-byte IV).

0x29890 is exactly the literal SaveLoadGame writes at 0x14640C into
param+0x78 / param+0x7C, so the game's own buffer size is now known.

Structural predictions already in hand from the EBOOT, to test against bytes:
  * SaveLoadGame memset()s 0x7E4 = 2020 bytes. And 0x28 + 99*20 = 40+1980 =
    2020 exactly - i.e. a 40-byte header followed by NINEVENTY-NINE 20-byte
    records. Its loop walks i = 0..98 (slti ... 0x63), tests bit i of a flag
    array (i>>5 word index, sllv 1<<(i&31) mask) and, for each set bit,
    processes a 20-byte record (s1 += 0x14). So look for 99 * 20 = 0x7BC
    bytes of record-shaped data.
  * SYSTEM save is plaintext even in the encrypted era, so it can be mapped
    regardless of the PPSSPP setting.

Produce: header word decode, a map of non-zero byte spans (data vs padding),
strings in ascii / utf-16le / cp932, and a field-level diff of the two game
saves. The diff matters most - two saves that differ only in progress expose
which offsets carry chapter / progress flags.
"""
import os
import re
import struct

ROOT = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
TARGETS = ['ULUS10656SN5GAME45', 'NPJH50696SN5GAME06',
           'ULUS10656SN5SYSTEM', 'NPJH50696SN5SYSTEM']


def load(n):
    p = os.path.join(ROOT, n, 'DATA.BIN')
    return open(p, 'rb').read() if os.path.isfile(p) else None


def spans(b, gap=64, minlen=4):
    """Group non-zero bytes into runs, merging runs separated by < gap zeros."""
    out, st, run = [], None, 0
    i = 0
    while i < len(b):
        if b[i] != 0:
            if st is None:
                st = i
            run = 0
        else:
            if st is not None:
                run += 1
                if run >= gap:
                    if i - run - st >= minlen:
                        out.append((st, i - run))
                    st = None
                run += 0
        i += 1
    if st is not None:
        out.append((st, len(b)))
    return out


def strings(b):
    out = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', b):
        out.append((m.start(), m.group().decode('latin-1')))
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', b):
        try:
            out.append((m.start(), m.group().decode('utf-16le')))
        except Exception:
            pass
    return sorted(out)


def entropy(b):
    if not b:
        return 0.0
    from collections import Counter
    import math
    c = Counter(b)
    n = float(len(b))
    return -sum((v / n) * math.log2(v / n) for v in c.values())


data = {n: load(n) for n in TARGETS}

for n in TARGETS:
    b = data[n]
    if b is None:
        print('%s -> missing' % n)
        continue
    print('=' * 74)
    print('%s   size=%d (0x%X)  entropy=%.4f' % (n, len(b), len(b), entropy(b)))
    print('=' * 74)

    print('  header words:')
    for i in range(0, 0x40, 4):
        w = struct.unpack_from('<I', b, i)[0]
        print('     +0x%02X  0x%08X  %10d' % (i, w, w))

    sp = spans(b)
    nz = sum(1 for x in b if x)
    print('  non-zero bytes: %d / %d (%.1f%%)' % (nz, len(b), 100.0 * nz / len(b)))
    print('  non-zero spans (>=4 bytes, gap 64): %d' % len(sp))
    for off, end in sp[:40]:
        seg = b[off:end]
        print('     0x%06X..0x%06X  len=%-6d ent=%.2f  %s'
              % (off, end - 1, len(seg), entropy(seg),
                 ' '.join('%02X' % x for x in seg[:16])))
    if len(sp) > 40:
        print('     ... %d more' % (len(sp) - 40))

    st = strings(b)
    print('  strings: %d' % len(st))
    for off, s in st[:25]:
        print('     0x%06X %r' % (off, s[:70]))
    print()

# ---- field-level diff of the two plaintext game saves -------------------
a, b = data['ULUS10656SN5GAME45'], data['NPJH50696SN5GAME06']
if a and b:
    m = min(len(a), len(b))
    print('=' * 74)
    print('DIFF  ULUS10656SN5GAME45  vs  NPJH50696SN5GAME06')
    print('=' * 74)
    diffs = []
    for i in range(0, m - 3, 4):
        wa = struct.unpack_from('<I', a, i)[0]
        wb = struct.unpack_from('<I', b, i)[0]
        if wa != wb:
            diffs.append((i, wa, wb))
    print('  differing aligned words: %d of %d' % (len(diffs), m // 4))
    for off, wa, wb in diffs[:60]:
        print('     +0x%06X  US=%-12d JP=%-12d   (0x%08X / 0x%08X)'
              % (off, wa, wb, wa, wb))
    if len(diffs) > 60:
        print('     ... %d more' % (len(diffs) - 60))
    # where do the diffs cluster?
    if diffs:
        print('  diff span: +0x%X .. +0x%X' % (diffs[0][0], diffs[-1][0]))
print('DONE')
