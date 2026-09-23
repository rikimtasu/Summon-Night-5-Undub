# -*- coding: utf-8 -*-
"""Find the decrypted save struct by measuring struct-likeness, not entropy.

Earlier attempts failed for two reasons:
  * plain entropy accepted 0xFF fill and untouched zero pages (both score 0)
  * the sliding-window scan was O(offsets x size) ~= 1e11 byte ops and simply
    never finished

Scoring a real save struct instead of raw entropy:
  * most 32-bit words are SMALL (upper half == 0): counters, flags, ids and
    index arrays. Ciphertext or compressed data never looks like that.
  * it holds a real mixture of zero and non-zero bytes (0.10 .. 0.90 zeros)
  * it is not dominated by one repeated byte value (rules out 0xFF fill)

All three statistics are computed once over the whole RAM image with
numpy cumulative sums, so evaluating every word-aligned window is O(n).

For each survivor we print the header bytes and the first non-zero runs, which
is what actually identifies the structure.
"""
import collections
import os
import struct
import sys

import numpy as np

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram

GAMESZ = 170144
SYSSZ = 22752


def score(ram, size, label, limit=8, dens_min=0.25):
    """Vectorised struct-likeness scan over every word-aligned offset.

    The metric is the fraction of words that are SMALL *AND* NON-ZERO
    (0 < x < 0x10000). That is the value that separates the three cases:

        real save struct   dense with counters/flags/ids  -> high
        all-zero / 0xFF pad all words zero or 0xFFFFFFFF   -> 0
        ciphertext          random u32, P(upper half 0)=1/65536 -> ~0

    Ranking on plain "small fraction" was useless: it scores all-zeros at
    1.000 and puts padding at the top of the list.
    """
    a = np.frombuffer(ram, dtype=np.uint8)
    nbytes = len(a)

    # --- zero-fraction over `size` bytes -----------------------------------
    is_zero = (a == 0).astype(np.int64)
    cz = np.concatenate(([0], np.cumsum(is_zero)))
    zf = (cz[size:nbytes] - cz[:nbytes - size]) / float(size)

    # --- small-non-zero-u32 fraction over `size/4` words -------------------
    wlen = size // 4
    words = np.frombuffer(ram, dtype=np.uint32, count=nbytes // 4)
    hit = (((words >> 16) == 0) & (words != 0)).astype(np.int64)
    cs = np.concatenate(([0], np.cumsum(hit)))
    nwin = len(hit) - wlen
    df_words = (cs[wlen:wlen + nwin] - cs[:nwin]) / float(wlen)

    # byte window b covers words b/4 .. b/4+wlen
    nwin_b = min(nwin, len(zf) // 4)
    dens = df_words[:nwin_b]
    z_at = zf[:nwin_b * 4:4][:nwin_b]

    # --- filters -----------------------------------------------------------
    keep = (dens > dens_min) & (z_at > 0.05) & (z_at < 0.85)
    idx = np.nonzero(keep)[0]
    print('\n=== %s (%d B): %d/%d windows pass the struct filters ==='
          % (label, size, len(idx), nwin_b))
    if len(idx) == 0:
        return

    # rank by density, but reject windows dominated by one byte value
    order = idx[np.argsort(dens[idx])[::-1]]
    picked = []
    for wi in order:
        b = int(wi * 4)
        w = ram[b:b + size]
        c = collections.Counter(w)
        if len(c) < 8:                       # solid fill, not a struct
            continue
        if c.most_common(1)[0][1] / float(size) > 0.50:
            continue
        if any(abs(b - p) < size for p in picked):   # collapse overlaps
            continue
        picked.append(b)
        if len(picked) >= limit:
            break

    for b in picked:
        w = ram[b:b + size]
        c = collections.Counter(w)
        topn = c.most_common(1)[0][1]
        print('  RAM 0x%08X  smallNonZero=%.3f zeros=%.3f distinct=%-3d topByte=%.2f'
              % (b, dens[b // 4], z_at[b // 4], len(c), topn / float(size)))
        print('      first 96 B: %s' % w[:96].hex())
        # first non-zero runs, which is where a header/field lives
        runs = []
        i = 0
        while i < len(w) and len(runs) < 6:
            if w[i]:
                j = i
                while j < len(w) and w[j]:
                    j += 1
                if j - i >= 4:
                    runs.append((i, j, w[i:min(j, i + 24)].hex()))
                i = j
            else:
                i += 1
        for (x, y, h) in runs:
            print('        nonzero 0x%05X..0x%05X (%d B) %s' % (x, y, y - x, h))


def main(stfile):
    ram = extract_ram(os.path.join(STATE, stfile))
    print('%s  RAM %d bytes' % (stfile, len(ram)))
    score(ram, GAMESZ, 'GAME')
    score(ram, SYSSZ, 'SYSTEM', limit=6)
    print('DONE')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'ULUS10656_1.01_0.ppst')
