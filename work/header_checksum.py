# -*- coding: utf-8 -*-
"""Identify header word +0x08, and confirm the header layout.

Header decoded so far (both plaintext game saves, 28 bytes = 0x1C):

    +0x00  0x00021001   same US/JP
    +0x04  0x00000002   same US/JP
    +0x08  US 0x00033FA0 (212896)  JP 0x00026E2E (159278)   DIFFERS
    +0x0C  0x00029874 = 170100 = filesize - 0x1C   (170128-28)  => payload size
    +0x10  0x13 (19)     same
    +0x14  0x12 (18)     same
    +0x18  0xDC (220)    same

+0x0C proves the header is exactly 0x1C bytes and the payload runs
0x1C .. 0x2988F. That is the first hard layout fact.

+0x08 is the risk field: if it is a checksum of the payload, any edit must
recompute it or the game will reject the save. Three independent plaintext
files give three data points - the two game saves (US/JP, different content)
plus SYSTEM, which was never encrypted in the first place.

So compute a battery of standard checksums over several candidate ranges and
report any that reproduce the stored value on ALL files. Candidates:
  byte sums, u16/u32 word sums, zlib crc32, zlib adler32, xor-fold, and
  position-weighted sums - each over {whole file, payload, payload+header
  excluding the field itself}.

A hit on one file only is a coincidence; only an all-file hit counts.
"""
import os
import zlib
import struct

ROOT = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
FILES = ['ULUS10656SN5GAME45', 'NPJH50696SN5GAME06',
         'ULUS10656SN5SYSTEM', 'NPJH50696SN5SYSTEM']


def load(n):
    p = os.path.join(ROOT, n, 'DATA.BIN')
    return open(p, 'rb').read() if os.path.isfile(p) else None


def u32(b, i):
    return struct.unpack_from('<I', b, i)[0]


def variants(b):
    """name -> value, for many candidate checksum definitions."""
    out = {}
    ranges = {
        'all': b,
        'pay': b[0x1C:],
        'no08': b[:0x08] + b[0x0C:],
        'pay_no08': b[0x1C:0x08 + 0] if False else b[0x1C:],
        'hdr16': b[:0x10],
        'first1m': b[:0x1000],
    }
    for nm, seg in ranges.items():
        if not seg:
            continue
        out['sum_%s' % nm] = sum(seg) & 0xFFFFFFFF
        out['crc32_%s' % nm] = zlib.crc32(seg) & 0xFFFFFFFF
        out['adler_%s' % nm] = zlib.adler32(seg) & 0xFFFFFFFF
        out['xor_%s' % nm] = 0
        x = 0
        for c in seg:
            x ^= c
        out['xor_%s' % nm] = x
        # u32 word sum (only when 4-aligned range)
        if len(seg) >= 4:
            n = len(seg) // 4
            s = 0
            for i in range(n):
                s += struct.unpack_from('<I', seg, i * 4)[0]
            out['wsum_%s' % nm] = s & 0xFFFFFFFF
            # word xor
            xw = 0
            for i in range(n):
                xw ^= struct.unpack_from('<I', seg, i * 4)[0]
            out['wxor_%s' % nm] = xw
    # position-weighted byte sum over payload
    s = 0
    for i, c in enumerate(b[0x1C:]):
        s = (s + c * (i + 1)) & 0xFFFFFFFF
    out['wpos_pay'] = s
    # sum of u16 over payload
    seg = b[0x1C:]
    n = len(seg) // 2
    s = 0
    for i in range(n):
        s += struct.unpack_from('<H', seg, i * 2)[0]
    out['hsum_pay'] = s & 0xFFFFFFFF
    # header-only combos
    out['hdr_pack'] = (u32(b, 0) ^ u32(b, 4) ^ u32(b, 0x10) ^ u32(b, 0x14)
                       ^ u32(b, 0x18))
    return out


data = {}
print('=== stored +0x08 values ===')
for n in FILES:
    b = load(n)
    if b is None:
        print('  %-24s missing' % n)
        continue
    data[n] = b
    print('  %-24s size=0x%X  +0x08=0x%08X (%d)  +0x0C=0x%08X  '
          'check size-0x1C=0x%X %s'
          % (n, len(b), u32(b, 8), u32(b, 8), u32(b, 0x0C), len(b) - 0x1C,
             'OK' if u32(b, 0x0C) == len(b) - 0x1C else 'MISMATCH'))

print('\n=== candidate checksums: which reproduce EVERY stored +0x08 ? ===')
allv = {}
for n, b in data.items():
    allv[n] = variants(b)

names = set()
for v in allv.values():
    names |= set(v)

hits = []
for nm in sorted(names):
    vals = [(n, allv[n].get(nm)) for n in allv]
    if any(v is None for _, v in vals):
        continue
    targets = {n: u32(data[n], 8) for n in allv}
    if all(v == targets[n] for n, v in vals):
        hits.append(nm)
    else:
        # also report near-misses: matches >= 2 of them
        m = sum(1 for n, v in vals if v == targets[n])
        if m >= 2:
            print('  partial (%d/%d): %-16s %s'
                  % (m, len(vals), nm,
                     ', '.join('%s=%08X' % (n, v) for n, v in vals)))

if hits:
    print('\n  FULL MATCH on all files: %s' % ', '.join(hits))
else:
    print('\n  no candidate reproduces +0x08 on every file')
    print('  -> +0x08 is probably not a simple checksum of the payload')

# print raw candidate values for manual comparison
print('\n=== raw values for inspection ===')
for nm in sorted(names):
    row = '  %-16s' % nm
    ok = True
    for n in allv:
        v = allv[n][nm]
        row += '  %s=%08X' % (n[:14], v)
        if v != u32(data[n], 8):
            ok = False
    if ok:
        row += '   <== equals +0x08 for all'
    print(row)
print('DONE')
