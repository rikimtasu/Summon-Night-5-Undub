# -*- coding: utf-8 -*-
"""Locate the save buffers in RAM by anchoring on the on-disk ciphertext.

The first attempt scored every 170144-byte window by entropy and simply found
untouched zero pages - useless, because unused heap dwarfs the real buffer.

Much stronger anchor: if the game still holds the RAW file it just read, then a
64-byte run of the on-disk DATA.BIN must appear verbatim somewhere in RAM.
Finding that occurrence gives the buffer base exactly (offset = hit - 0), no
heuristics involved. Then:
  - the DECRYPTED copy is usually a second buffer, often allocated right after
    or right before the raw one, so scan the neighbourhood for a same-sized
    low-entropy block;
  - if the raw buffer is gone, fall back to scanning for ANY 170144-byte
    window that is neither all-zero nor high-entropy, i.e. a real struct.
"""
import collections
import math
import os
import sys

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
SAVE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA\ULUS10656SN5GAME46\DATA.BIN'
SAVESIZE = 170144
sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def find_all(hay, needle):
    out = []
    s = 0
    while True:
        i = hay.find(needle, s)
        if i < 0:
            break
        out.append(i)
        s = i + 1
    return out


save = open(SAVE, 'rb').read()
print('on-disk DATA.BIN %d bytes' % len(save))

# several probes at different offsets, in case only part is resident
probes = [(0, 64), (0x100, 64), (0x8000, 64), (0x10000, 64), (0x20000, 64)]

for st in ('ULUS10656_1.01_0.ppst', 'ULUS10656_1.01_1.ppst', 'ULUS10656_1.01_3.ppst'):
    p = os.path.join(STATE, st)
    if not os.path.isfile(p):
        continue
    ram = extract_ram(p)
    print('\n=== %s ===' % st)
    for off, ln in probes:
        nd = save[off:off + ln]
        hits = find_all(ram, nd)
        if hits:
            for h in hits:
                # the hit may be at any position inside the buffer; the probe
                # offset is known so the buffer base is hit-off (mod alignment)
                base = h - off
                print('  probe save+0x%05X found at RAM 0x%08X -> buffer base ~0x%08X'
                      % (off, h, base))
    # fallback: non-trivial low-entropy 170144 windows
    best = []
    step = 0x1000
    for off in range(0, len(ram) - SAVESIZE, step):
        w = ram[off:off + SAVESIZE]
        z = w.count(0)
        if z > SAVESIZE * 0.98:          # skip untouched pages
            continue
        e = entropy(w)
        if e < 6.0:
            best.append((e, off, z))
    best.sort()
    print('  -- non-trivial low-entropy 170144B windows --')
    for e, off, z in best[:6]:
        print('     RAM 0x%08X ent=%.3f zeros=%.1f%%' % (off, e, 100.0 * z / SAVESIZE))
    if not best:
        print('     none (save buffer not resident in this state)')
print('DONE')
