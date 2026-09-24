# -*- coding: utf-8 -*-
"""Express the controlled A/B/C diff as property ids.

property[i] lives at file offset 0x10 + i*4 for i = 0..229 (ends 0x3A8), so any
differing word inside that window can be named by its id. Words after 0x3A8 are
outside the property array (the 0x984-stride records and later structs) and are
listed separately with their record context.

    A = ULUS10656SN5GAME44   control 1 (08:11:55)
    B = ULUS10656SN5GAME43   control 2 (08:12:02, nothing done)
    C = ULUS10656SN5GAME42   start of chapter 2 (16:42:03)

    NOISE    = A ^ B
    PROGRESS = (diff(A,C) & diff(B,C)) - NOISE

Cross-reference the ids against scan_accessors.py, which lists every
get(obj,id)/set(obj,id,val) call site and the strings and tables around it.
"""
import os
import struct

ROOT = (r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick'
        r'\PSP\SAVEDATA')
A, B, C = 'ULUS10656SN5GAME44', 'ULUS10656SN5GAME43', 'ULUS10656SN5GAME42'

P_START, P_COUNT = 0x10, 230        # property array window
P_END = P_START + P_COUNT * 4       # 0x3A8
REC, PAY = 0x984, 0x1C

# ids already pinned down, from the save-slot description builder
KNOWN = {20: 'CHAPTER (drives resume + label)', 50: 'bucketed vs 40/80/100/200'}


def load(n):
    return open(os.path.join(ROOT, n, 'DATA.BIN'), 'rb').read()


def words(b):
    return list(struct.unpack_from('<%dI' % (len(b) // 4), b, 0))


def diff(x, y):
    return set(i for i in range(min(len(x), len(y))) if x[i] != y[i])


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


def main():
    wa, wb, wc = words(load(A)), words(load(B)), words(load(C))
    noise = diff(wa, wb)
    progress = (diff(wa, wc) & diff(wb, wc)) - noise

    print('=' * 78)
    print('PROGRESS WORDS AS PROPERTY IDS   (progress=%d  noise=%d)'
          % (len(progress), len(noise)))
    print('=' * 78)

    in_prop = [i for i in progress if P_START // 4 <= i < P_END // 4]
    out_prop = [i for i in progress if i not in set(in_prop)]

    print()
    print('--- INSIDE the property array (id = (off-0x10)/4): %d words ---'
          % len(in_prop))
    print('   id   offset     A/B            C            delta')
    for i in sorted(in_prop):
        off, pid = i * 4, i * 4 // 4 - P_START // 4
        a, c = wa[i], wc[i]
        note = KNOWN.get(pid, '')
        if pid in KNOWN:
            note = KNOWN[pid]
        # signed + unsigned delta, both are informative for counters
        d = (c - a) & 0xFFFFFFFF
        ds = c - a
        print('  %4d  0x%05X   0x%08X -> 0x%08X  (%+d)  %s'
              % (pid, off, a, c, ds, note))
        if a and c and a <= 0xFFFF and c <= 0xFFFF:
            print('        %-14s decimal %d -> %d' % ('', a, c))

    print()
    print('--- OUTSIDE the property array: %d words ---' % len(out_prop))
    for a, b in runs(set(out_prop)):
        off = a * 4
        if off < P_START:
            label = 'HEADER'
        else:
            r, o = divmod(off - PAY, REC)
            label = 'rec#%d+0x%X' % (r, o)
        print('  +0x%06X..+0x%06X len=%-4d %s'
              % (off, b * 4 + 3, (b - a + 1) * 4, label))
        for k in range(a, min(b + 1, a + 8)):
            print('        +0x%06X   A/B=0x%08X   C=0x%08X'
                  % (k * 4, wa[k], wc[k]))
        if b - a + 1 > 8:
            print('        ... %d more words' % (b - a + 1 - 8))

    print()
    print('=' * 78)
    print('UNCHANGED property ids worth naming anyway (non-zero in A): '
          'sample')
    print('=' * 78)
    shown = 0
    for pid in range(P_COUNT):
        i = P_START // 4 + pid
        if i in progress or not wa[i]:
            continue
        print('  %4d  0x%05X = 0x%08X (%d)' % (pid, i * 4, wa[i], wa[i]))
        shown += 1
        if shown >= 40:
            print('  ...')
            break
    print('DONE')


if __name__ == '__main__':
    main()
