# -*- coding: utf-8 -*-
"""Hunt the save buffers in a save state taken on the load/save screen.

Mid-game states held neither the raw ciphertext nor a plaintext copy: the game
reads the file, parses it into its own structures, and frees the buffer. A
state captured while the load screen is up should still have the buffer(s)
alive, so this state is the one that can actually yield plaintext.

Three independent searches, because we don't know which representation is
resident:

  A. RAW CIPHERTEXT - a 64-byte run of the on-disk DATA.BIN found verbatim in
     RAM pins the raw read buffer's base exactly (hit - probe_offset).
  B. PLAINTEXT STRUCT - a 170144-byte window that is neither all-zero nor
     high-entropy. A real save struct is counters/flags/zero padding, so it
     scores clearly below ciphertext but clearly above untouched heap.
  C. SYSTEM SAVE - same idea at 22752 bytes for ULUS10656SN5SYSTEM.

For any plaintext candidate, report the zero fraction, the count of distinct
byte values, and the first/last non-zero extents, so we can tell a real struct
from sparse heap immediately.
"""
import collections
import math
import os
import sys

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
SD = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
GAME = os.path.join(SD, 'ULUS10656SN5GAME46', 'DATA.BIN')
SYS = os.path.join(SD, 'ULUS10656SN5SYSTEM', 'DATA.BIN')
GAMESZ = 170144
SYSSZ = 22752

sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def describe(tag, ram, off, size):
    w = ram[off:off + size]
    z = w.count(0)
    nz = [i for i, b in enumerate(w) if b]
    lo = nz[0] if nz else -1
    hi = nz[-1] if nz else -1
    print('  %s RAM 0x%08X size=%d' % (tag, off, size))
    print('      entropy=%.3f  zeros=%.1f%%  distinct=%d  nonzero extent=0x%X..0x%X'
          % (entropy(w), 100.0 * z / size, len(set(w)), lo, hi))
    print('      head: %s' % w[:48].hex())
    return w


def main(stfile):
    p = os.path.join(STATE, stfile)
    ram = extract_ram(p)
    print('=== %s  RAM %d bytes ===' % (stfile, len(ram)))

    game = open(GAME, 'rb').read()
    sysb = open(SYS, 'rb').read()

    print('\n--- A. raw ciphertext runs ---')
    for name, blob, probes in (('GAME', game, (0, 0x40, 0x100, 0x1000, 0x8000,
                                            0x10000, 0x20000, 0x28000)),
                               ('SYSTEM', sysb, (0, 0x40, 0x100, 0x1000, 0x4000))):
        for po in probes:
            nd = blob[po:po + 48]
            s = 0
            while True:
                i = ram.find(nd, s)
                if i < 0:
                    break
                print('  %s probe +0x%05X found at RAM 0x%08X (base ~0x%08X)'
                      % (name, po, i, i - po))
                s = i + 1

    print('\n--- B. plaintext-sized low-entropy windows ---')
    for size, label in ((GAMESZ, 'GAME'), (SYSSZ, 'SYSTEM')):
        cands = []
        for off in range(0, len(ram) - size, 0x200):
            w = ram[off:off + size]
            z = w.count(0)
            if z > size * 0.90:          # sparse/unused
                continue
            e = entropy(w)
            if e < 5.5:
                cands.append((e, off, z))
        cands.sort()
        print('  %s (%d B): %d candidates' % (label, size, len(cands)))
        for e, off, z in cands[:6]:
            describe(label, ram, off, size)
    print('DONE')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'ULUS10656_1.01_0.ppst')
