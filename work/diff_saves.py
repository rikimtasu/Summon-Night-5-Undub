# -*- coding: utf-8 -*-
"""Byte-level diff of two or more plaintext SN5 game saves.

Usage:
    python diff_saves.py ULUS10656SN5GAME45 ULUS10656SN5GAME48 [more ...]

Each argument is a directory under the PPSSPP SAVEDATA root containing a
DATA.BIN. Files are compared as aligned little-endian u32 words.

Why this is the decisive tool
-----------------------------
The save format is now known (see RE_notes.md):

    header  0x1C bytes:  +0x00 0x00021001, +0x04 2, +0x08 varies,
            +0x0C = filesize-0x1C, +0x10 19, +0x14 18, +0x18 220
    payload 0x1C .. 0x2988F
    records stride 0x984 = 2436 bytes, with a sequential index at +12
            (... FF FF 00 00 | index ...)

and from the EBOOT, SaveLoadGame memsets 0x7E4 = 0x28 + 99*20 exactly, then
loops i = 0..98 testing bit i of a flag array (i>>5 word index, 1<<(i&31)
mask) and processing a 20-byte record for each set bit. So the chapter /
progress flags are expected either as a dense 99-bit bit array (13 bytes,
3 words) or as the +0x64 / +0x7C / +0xA8 / +0xE0 style counters already seen.

US-vs-JP diffs are useless for this: two different-region saves differ at
1101 words for reasons unrelated to progress. What isolates a chapter flag is
a *same-playthrough* pair. With three files the discrimination is much better:

    - differs in EVERY pair     -> genuine state (progress/chapter candidate)
    - differs in only some pair -> noise: playtime, RNG seed, position, party

So feed it 3 files if you have them: A (save), B (save again immediately, a
control), C (after clearing a chapter). Then A<->B is noise only, and
(A,C) minus (A,B) is the progress delta.

Also reports fields that increase monotonically in the order given, since a
chapter counter does exactly that.
"""
import os
import struct
import sys

ROOT = (r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick'
        r'\PSP\SAVEDATA')

HDR_FIELDS = [0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18]


def load(name):
    p = os.path.join(ROOT, name, 'DATA.BIN')
    if not os.path.isfile(p):
        return None
    return open(p, 'rb').read()


def words(b):
    n = len(b) // 4
    return list(struct.unpack_from('<%dI' % n, b, 0))


def group_runs(idxs, gap=4):
    """Group word indices into runs; gap = max missing words inside a run."""
    if not idxs:
        return []
    runs, start, prev = [], idxs[0], idxs[0]
    for i in idxs[1:]:
        if i - prev > gap:
            runs.append((start, prev))
            start = i
        prev = i
    runs.append((start, prev))
    return runs


def main(argv):
    names = argv
    if len(names) < 2:
        print(__doc__)
        print('ERROR: need at least two save directory names')
        return 2

    data, ws = [], []
    for n in names:
        b = load(n)
        if b is None:
            print('MISSING: %s' % n)
            return 1
        data.append(b)
        ws.append(words(b))

    print('=' * 78)
    print('FILES (%d)' % len(data))
    print('=' * 78)
    for n, b in zip(names, data):
        print('  %-24s size=0x%X (%d)' % (n, len(b), len(b)))

    sizes = set(len(b) for b in data)
    if len(sizes) > 1:
        print('  !! sizes differ, comparing only the common prefix')

    # ---- header ----------------------------------------------------------
    print()
    print('=' * 78)
    print('HEADER (+0x00 .. +0x18)')
    print('=' * 78)
    for off in HDR_FIELDS:
        vals = [struct.unpack_from('<I', b, off)[0] for b in data]
        same = len(set(vals)) == 1
        print('  +0x%02X  %-38s %s'
              % (off,
                 '  '.join('%s=0x%08X' % (n[:8], v) for n, v in zip(names, vals)),
                 'same' if same else '<-- DIFFERS'))

    # ---- aligned word diff ----------------------------------------------
    n = min(len(w) for w in ws)
    diff_idx = []
    for i in range(n):
        if len(set(w[i] for w in ws)) > 1:
            diff_idx.append(i)

    total = n
    print()
    print('=' * 78)
    print('WORD DIFF')
    print('=' * 78)
    print('  differing aligned words: %d / %d (%.2f%%)'
          % (len(diff_idx), total, 100.0 * len(diff_idx) / total))
    print('  identical words        : %d' % (total - len(diff_idx)))

    runs = group_runs(diff_idx, gap=4)
    print('  differing regions (gap<=4 words): %d' % len(runs))
    print()

    # ---- classification with >=3 files -----------------------------------
    nfiles = len(ws)
    pair_all_differ = None
    if nfiles >= 3:
        # a word "counts as differing" in pair (i,j) if ws[i][k] != ws[j][k]
        pairs = [(i, j) for i in range(nfiles) for j in range(i + 1, nfiles)]
        allp, somep = [], []
        for k in diff_idx:
            d = [ws[i][k] != ws[j][k] for i, j in pairs]
            if all(d):
                allp.append(k)
            else:
                somep.append(k)
        pair_all_differ = (allp, somep)
        print('  with %d files, %d pairs:' % (nfiles, len(pairs)))
        print('    differ in EVERY pair (progress/state candidates): %d' % len(allp))
        print('    differ in only some pair (noise: time/RNG/pos)  : %d' % len(somep))
        print()

    # ---- per-region detail ------------------------------------------------
    print('=' * 78)
    print('DIFFERING REGIONS')
    print('=' * 78)
    shown = 0
    MAXREG = 80
    for a, b in runs:
        off = a * 4
        end = b * 4 + 3
        if off < 0x1C:
            loc = 'HEADER'
        else:
            rec = (off - 0x1C) // 0x984
            rin = (off - 0x1C) % 0x984
            loc = 'payload rec#%d+0x%X' % (rec, rin)
        print('  +0x%06X..+0x%06X  len=%-5d  %s' % (off, end, end - off + 1, loc))
        show = list(range(a, min(b + 1, a + 8)))
        for k in show:
            vals = '  '.join('%08X' % w[k] for w in ws)
            tag = ''
            if pair_all_differ is not None:
                tag = '  <== ALL PAIRS DIFFER' if k in pair_all_differ[0] else ''
            print('        +0x%06X  %s%s' % (k * 4, vals, tag))
        if b - a + 1 > 8:
            print('        ... %d more words' % (b - a + 1 - 8))
        shown += 1
        if shown >= MAXREG:
            print('  ... (%d more regions suppressed)' % (len(runs) - shown))
            break

    # ---- monotone fields --------------------------------------------------
    print()
    print('=' * 78)
    print('STRICTLY INCREASING FIELDS (chapter/progress counter signature)')
    print('=' * 78)
    inc = []
    for k in range(n):
        vs = [w[k] for w in ws]
        if len(set(vs)) > 1 and all(vs[i] < vs[i + 1] for i in range(len(vs) - 1)):
            inc.append((k * 4, vs))
    if not inc:
        print('  none (expected if only 2 files, or if order is wrong)')
    for off, vs in inc[:60]:
        loc = 'HEADER' if off < 0x1C else 'rec#%d+0x%X' % ((off - 0x1C) // 0x984,
                                                            (off - 0x1C) % 0x984)
        print('  +0x%06X  %-22s  %s' % (off, loc,
                                         ' -> '.join('%d' % v for v in vs)))
    print()
    print('  NOTE: order matters - pass files in progress order.')
    print('DONE')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
