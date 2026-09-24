# -*- coding: utf-8 -*-
"""Measure record stride and locate data regions in the plaintext saves.

Established so far:
  header = 0x1C bytes; +0x0C = filesize - 0x1C (payload length), confirmed on
  both game saves (170128 - 28 = 170100 = 0x29874)
  SYSTEM save contains arrays of 540-byte records: span starts at
  0x278, 0x494, 0x6B0, 0x8CC, 0xAE8, 0xD04, 0xF20, 0x113C, 0x1358, 0x1574,
  0x1790, 0x19AC, 0x1DE4 - every consecutive step is exactly 0x21C = 540,
  with 0x1DE4 = 0x19AC + 2*0x21C (one empty slot skipped).
  Record shape: 01 00 | f2 | 04 00 00 00 | 14 00 | index | 3C 00 | flag

The GAME save clearly uses a *different* record size (its span starts step by
0xC4 = 196 around 0x6082). So measure the dominant stride directly instead of
guessing: build a non-zero byte mask and autocorrelate it over every 4-byte
lag up to 0x800. A record array produces a sharp peak at its stride and
harmonics at 2x/3x. This is validated by running it on SYSTEM first, which
must report 0x21C.

Then report, per file: the top periodicity peaks, the data spans (so we can
see which parts of the 170128 bytes actually carry state), and the header
field values that differ between the two game saves.

Motivation for the diff: US GAME45 and JP GAME06 differ at 1101 aligned
words. Early fields that differ include +0x64 (30 vs 20), +0x7C (4 vs 2),
+0xA8/+0xAC (16518 vs 130), +0xE0 (1000 vs 0), +0x108 (4 vs 3),
+0x110 (8 vs 2) - candidate progress/chapter counters - but two different
region saves differ in many ways, so a same-region, two-progress-point pair
is what will actually pin the chapter flag down.
"""
import os
import struct
import collections

ROOT = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
FILES = ['ULUS10656SN5GAME45', 'NPJH50696SN5GAME06',
         'ULUS10656SN5SYSTEM', 'NPJH50696SN5SYSTEM']


def load(n):
    p = os.path.join(ROOT, n, 'DATA.BIN')
    return open(p, 'rb').read() if os.path.isfile(p) else None


def periodicity(b, maxlag=0x800):
    """Peak lags where non-zero bytes recur - i.e. record strides."""
    nz = bytearray(len(b))
    for i, c in enumerate(b):
        if c:
            nz[i] = 1
    n = len(b)
    # prefix sums for O(1) window counts
    ps = [0] * (n + 1)
    for i in range(n):
        ps[i + 1] = ps[i] + nz[i]
    res = []
    for L in range(4, maxlag + 1, 4):
        # score = how many i have nz[i] and nz[i+L]
        cnt = 0
        i = 0
        # scan only non-zero positions
        while i < n:
            if nz[i]:
                if i + L < n and nz[i + L]:
                    cnt += 1
                i += 1
            else:
                i += 1
        res.append((cnt, L))
    res.sort(reverse=True)
    return res


def data_spans(b, gap=256, minlen=16):
    out, st, z = [], None, 0
    for i, c in enumerate(b):
        if c != 0:
            if st is None:
                st = i
            z = 0
        elif st is not None:
            z += 1
            if z >= gap:
                if i - z - st >= minlen:
                    out.append((st, i - z))
                st = None
    if st is not None:
        out.append((st, len(b)))
    return out


for n in FILES:
    b = load(n)
    if b is None:
        print('%s missing' % n)
        continue
    print('=' * 76)
    print('%s  size=0x%X  nonzero=%d (%.1f%%)'
          % (n, len(b), sum(1 for c in b if c),
             100.0 * sum(1 for c in b if c) / len(b)))
    print('=' * 76)

    print('  header:')
    for i in (0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18):
        print('     +0x%02X = 0x%08X (%d)' % (i, struct.unpack_from('<I', b, i)[0],
                                              struct.unpack_from('<I', b, i)[0]))

    top = periodicity(b, 0x800)
    print('  top periodicity peaks (lag -> count of coincident non-zero bytes):')
    for cnt, L in top[:14]:
        print('     lag 0x%-5X (%-5d) score=%d' % (L, L, cnt))

    sp = data_spans(b)
    print('  data spans (gap>=256 zeros): %d' % len(sp))
    tot = 0
    for off, end in sp:
        tot += end - off
        print('     0x%06X..0x%06X  len=%-6d' % (off, end - 1, end - off))
    print('     total span bytes = %d / %d (%.1f%%)'
          % (tot, len(b), 100.0 * tot / len(b)))
    print()

# stride histogram from span starts, to cross-check the autocorrelation
print('=' * 76)
print('span-start difference histogram (should show the record stride)')
print('=' * 76)
for n in FILES:
    b = load(n)
    if b is None:
        continue
    sp = data_spans(b)
    starts = [o for o, _ in sp]
    d = collections.Counter(starts[i + 1] - starts[i]
                            for i in range(len(starts) - 1))
    print('  %s:' % n)
    for delta, c in d.most_common(8):
        print('      delta 0x%-6X (%-5d) x%d%s'
              % (delta, delta, c,
                 '   <-- record stride' if c >= 3 else ''))
print('DONE')
