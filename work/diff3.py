# -*- coding: utf-8 -*-
"""Three-file controlled diff: separate progress state from save-time noise.

Given
    A = ULUS10656SN5GAME44   control save #1 (8:11:55)
    B = ULUS10656SN5GAME43   control save #2 (8:12:02, 7s later, nothing done)
    C = ULUS10656SN5GAME42   after advancing to start of chapter 2 (16:42:03)

the correct partition is NOT "differs in every pair":

    NOISE     N = diff(A,B)              # whatever changes on its own
    PROGRESS  P = (diff(A,C) & diff(B,C)) - N
              i.e. C moved away from BOTH controls, and the controls agreed
              with each other there.

Anything in diff(A,C) but not in diff(B,C) is by definition unstable and
cannot be trusted as progress.

Output: pairwise sizes, the noise list, the progress list grouped into regions
(with record/offset context from the known layout), and the header decode.
"""
import os
import struct

ROOT = (r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick'
        r'\PSP\SAVEDATA')
A = 'ULUS10656SN5GAME44'
B = 'ULUS10656SN5GAME43'
C = 'ULUS10656SN5GAME42'

PAY = 0x1C
REC = 0x984          # record stride measured in analyze_records.py


def load(n):
    return open(os.path.join(ROOT, n, 'DATA.BIN'), 'rb').read()


def W(b):
    n = len(b) // 4
    return list(struct.unpack_from('<%dI' % n, b, 0))


def dset(x, y):
    return set(k for k in range(min(len(x), len(y))) if x[k] != y[k])


def runs(idxs, gap=4):
    idxs = sorted(idxs)
    if not idxs:
        return []
    out, s, p = [], idxs[0], idxs[0]
    for i in idxs[1:]:
        if i - p > gap:
            out.append((s, p))
            s = i
        p = i
    out.append((s, p))
    return out


def where(off):
    if off < PAY:
        return 'HEADER'
    r, o = divmod(off - PAY, REC)
    return 'rec#%d+0x%X' % (r, o)


da, db, dc = load(A), load(B), load(C)
wa, wb, wc = W(da), W(db), W(dc)
names = [A, B, C]
ws = [wa, wb, wc]

nAB, nAC, nBC = dset(wa, wb), dset(wa, wc), dset(wb, wc)
noise = nAB
progress = ((nAC & nBC) - noise)
unstable = (nAC ^ nBC) - noise      # differs with exactly one control

print('=' * 78)
print('PAIRWISE DIFF (aligned u32 words)')
print('=' * 78)
print('  A vs B  (control, 7s apart, nothing done) : %d' % len(nAB))
print('  A vs C  (progress + noise)                : %d' % len(nAC))
print('  B vs C  (progress + noise)                : %d' % len(nBC))
print('  intersection A&C and B&C                  : %d' % len(nAC & nBC))
print('  NOISE      = A^B                          : %d' % len(noise))
print('  PROGRESS   = (A&C & B&C) - noise          : %d' % len(progress))
print('  UNSTABLE   = (A&C sym-diff B&C) - noise   : %d' % len(unstable))
print('  words examined                            : %d' % len(wa))

for label, s in (('NOISE', noise), ('PROGRESS', progress), ('UNSTABLE', unstable)):
    print()
    print('=' * 78)
    print('%s  (%d words, %d regions)' % (label, len(s), len(runs(s))))
    print('=' * 78)
    for a, b in runs(s):
        off = a * 4
        print('  +0x%06X..+0x%06X len=%-4d %s'
              % (off, b * 4 + 3, (b - a + 1) * 4, where(off)))
        for k in range(a, min(b + 1, a + 6)):
            print('        +0x%06X   A=%08X  B=%08X  C=%08X%s'
                  % (k * 4, wa[k], wb[k], wc[k],
                     '   [in NOISE]' if k in noise else ''))
        if b - a + 1 > 6:
            print('        ... %d more words' % (b - a + 1 - 6))

print()
print('=' * 78)
print('HEADER')
print('=' * 78)
for off in (0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18):
    vs = [struct.unpack_from('<I', b, off)[0] for b in (da, db, dc)]
    tag = []
    if vs[0] != vs[1]:
        tag.append('NOISE')
    if vs[0] == vs[1] and vs[0] != vs[2]:
        tag.append('PROGRESS')
    print('  +0x%02X  A=0x%08X  B=0x%08X  C=0x%08X   %s'
          % (off, vs[0], vs[1], vs[2], ','.join(tag) or 'stable'))

# playtime check: A->B was 7 seconds of wall clock
print()
print('  +0x08 delta A->B = %d ; wall clock 7 s => %.1f units/s'
      % (struct.unpack_from('<I', db, 8)[0] - struct.unpack_from('<I', da, 8)[0],
         (struct.unpack_from('<I', db, 8)[0]
          - struct.unpack_from('<I', da, 8)[0]) / 7.0))
print('  +0x08 A->C = %d units = %.1f min at 60/s'
      % (struct.unpack_from('<I', dc, 8)[0] - struct.unpack_from('<I', da, 8)[0],
         (struct.unpack_from('<I', dc, 8)[0]
          - struct.unpack_from('<I', da, 8)[0]) / 60.0 / 60.0))

# 99-bit flag array hunt: look for 3-word windows whose bits flipped C vs A/B
print()
print('=' * 78)
print('BIT-FLIP SCAN (99-bit flag array candidate)')
print('=' * 78)
print('  words where C differs from BOTH controls by a small mask:')
n = 0
for k in sorted(progress):
    xa, xc = wa[k], wc[k]
    x = xa ^ xc
    if x and x < (1 << 32):
        n += 1
        if n <= 40:
            print('    +0x%06X %-12s A=%08X -> C=%08X  xor=%08X bits=%s'
                  % (k * 4, where(k * 4), xa, xc, x,
                     ''.join('1' if (x >> i) & 1 else '.'
                             for i in range(32))))
print('  total: %d' % n)
print('DONE')
