# -*- coding: utf-8 -*-
"""Reconnaissance pass over the load-screen save state.

Before guessing at struct metrics, answer three concrete questions:

  1. Which on-disk save files have any bytes resident in RAM at all? Probe
     every DATA.BIN on disk (all USA + JP slots) with several 48-byte windows.
     A hit pins the raw read buffer exactly; no hit means the game either has
     not read the file yet or has already freed/re-encrypted it.

  2. What save-derived STRINGS are in RAM? The EBOOT is mapped inside the RAM
     image at offset 0x804000..0xA46D54, and every static string (chapter
     titles, "Save Data", path templates) lives there - so a hit in that range
     proves nothing. Strings outside it are runtime-built: directory names,
     formatted paths, the SFO title, anything the loader printed.

  3. Is there a 170144-byte window that is HIGH entropy (the raw buffer if the
     file was read but not yet overwritten) versus one that is dense with small
     non-zero words (the parsed struct)?

The EBOOT mapping matters for (2): runtime fva F sits at RAM offset
(F + 0xC0 + 0x804000 - 0xC0) = 0x804000 + F, so the exclusion band is
0x804000 .. 0x804000 + 0x242C94.
"""
import collections
import math
import os
import re
import sys

import numpy as np

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
SD = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram

EBOOT_LO = 0x804000
EBOOT_HI = 0x804000 + 0x242D00
GAMESZ = 170144


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main(stfile):
    ram = extract_ram(os.path.join(STATE, stfile))
    print('%s  RAM %d bytes (0x%X)' % (stfile, len(ram), len(ram)))

    # ---- 1. probe every on-disk save against RAM -------------------------
    print('\n--- 1. on-disk save bytes resident in RAM? ---')
    probes = (0, 0x40, 0x100, 0x800, 0x1000, 0x8000, 0x10000, 0x20000)
    any_hit = False
    for d in sorted(os.listdir(SD)):
        f = os.path.join(SD, d, 'DATA.BIN')
        if not os.path.isfile(f):
            continue
        blob = open(f, 'rb').read()
        hits = []
        skipped = 0
        for po in probes:
            nd = blob[po:po + 48]
            if len(nd) < 48:
                continue
            # a needle that is mostly one byte value (all-zero padding) matches
            # millions of times and is meaningless - require a real probe
            if entropy(nd) < 4.0:
                skipped += 1
                continue
            s = 0
            while len(hits) < 40:
                i = ram.find(nd, s)
                if i < 0:
                    break
                hits.append((po, i))
                s = i + 1
        tag = 'HIT ' if hits else '    '
        print('  %s %-22s %8d B  hits=%d%s'
              % (tag, d, len(blob), len(hits),
                 ' (%d low-entropy probes skipped)' % skipped if skipped else ''))
        for po, i in hits:
            any_hit = True
            print('        save+0x%05X at RAM 0x%08X (base ~0x%08X)'
                  % (po, i, i - po))
    if not any_hit:
        print('  => NO raw save file bytes resident anywhere in RAM')

    # ---- 2. runtime-built strings ---------------------------------------
    print('\n--- 2. strings outside the EBOOT mapping (runtime-built) ---')
    seen = []
    for m in re.finditer(rb'[\x20-\x7e]{6,}', ram):
        if EBOOT_LO <= m.start() < EBOOT_HI:
            continue
        s = m.group()
        if any(k in s for k in (b'SAVEDATA', b'ms0:', b'ULUS10656', b'NPJH50696',
                                b'SN5GAME', b'SN5SYSTEM', b'DATA.BIN', b'PARAM',
                                b'Ch. ', b'Summon', b'PSP/GAME', b'PPSSPP')):
            seen.append((m.start(), s))
    print('  %d matches' % len(seen))
    for off, s in seen[:40]:
        print('    RAM 0x%08X  %r' % (off, s[:90]))

    # ---- 3. high-entropy 170144 windows (raw buffer if present) ---------
    print('\n--- 3. high-entropy 170144B windows (would be raw ciphertext) ---')
    a = np.frombuffer(ram, dtype=np.uint8)
    step = 0x1000
    best = []
    for off in range(0, len(ram) - GAMESZ, step):
        e = entropy(ram[off:off + GAMESZ])
        if e > 7.9:
            best.append((e, off))
    best.sort(reverse=True)
    print('  %d windows above ent 7.9 (step 0x1000)' % len(best))
    for e, off in best[:8]:
        print('    RAM 0x%08X ent=%.4f' % (off, e))

    # ---- 4. dense small-non-zero windows, relaxed ------------------------
    print('\n--- 4. dense small-non-zero-u32 170144B windows (parsed struct) ---')
    wlen = GAMESZ // 4
    words = np.frombuffer(ram, dtype=np.uint32, count=len(ram) // 4)
    hit = (((words >> 16) == 0) & (words != 0)).astype(np.int64)
    cs = np.concatenate(([0], np.cumsum(hit)))
    nwin = len(hit) - wlen
    dens = (cs[wlen:wlen + nwin] - cs[:nwin]) / float(wlen)
    is_zero = (a == 0).astype(np.int64)
    cz = np.concatenate(([0], np.cumsum(is_zero)))
    zf = (cz[GAMESZ:len(ram)] - cz[:len(ram) - GAMESZ]) / float(GAMESZ)
    nb = min(len(dens), len(zf) // 4)
    d = dens[:nb]
    z = zf[:nb * 4:4][:nb]
    keep = np.nonzero((d > 0.15) & (z > 0.05) & (z < 0.85))[0]
    print('  %d windows (dens>0.15, 0.05<zeros<0.85)' % len(keep))
    order = keep[np.argsort(d[keep])[::-1]]
    picked = []
    for wi in order:
        b = int(wi * 4)
        w = ram[b:b + GAMESZ]
        c = collections.Counter(w)
        if len(c) < 8 or c.most_common(1)[0][1] / float(GAMESZ) > 0.5:
            continue
        if any(abs(b - p) < GAMESZ for p in picked):
            continue
        picked.append(b)
        if len(picked) >= 6:
            break
    for b in picked:
        w = ram[b:b + GAMESZ]
        c = collections.Counter(w)
        print('  RAM 0x%08X dens=%.3f zeros=%.3f distinct=%-3d topByte=%.2f ent=%.3f'
              % (b, d[b // 4], z[b // 4], len(c),
                 c.most_common(1)[0][1] / float(GAMESZ), entropy(w)))
        print('      first 96 B: %s' % w[:96].hex())
    print('DONE')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'ULUS10656_1.01_0.ppst')
