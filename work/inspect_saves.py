# -*- coding: utf-8 -*-
"""Inspect the real save files to settle whether DATA.BIN is encrypted at all.

Static analysis of the EBOOT just found no transform loop anywhere in the save
path: SaveLoadGame/SaveLoadSystem/SaveLoadSuspend contain 0/1/0 XORs, and the
seven callees they share are the savedata state machine, two tiny accessors,
a memory op (184 callers), a 27-callsite helper, an 18-instruction function
called 408 times, and printf. SaveLoadSuspend has no backward branch at all, so
it cannot loop over a 170 KB buffer.

Which makes the "encrypted save" premise itself suspect. High entropy alone does
not mean encryption - it also matches compression, or a file that is mostly
uninitialised RAM contents (which look random but are stable per boot pattern).

So measure the files directly:
  * per-file size, sha1, entropy (whole file and first 4 KiB)
  * magic / structure at offset 0 (zlib 78 9C|DA|01, gzip 1F 8B, LZMA 5D 00,
    PSP PARAM.SFO 00 50 53 50)
  * ECB test: fraction of DISTINCT 16-byte blocks. Repeats => blocks are
    encrypted independently (ECB). Near-100% distinct does NOT prove
    anything on its own, but any repetition at all kills the
    "per-save keystream" claim for those bytes.
  * 4-byte alignment histogram bias: a plaintext structured struct shows
    obvious per-offset byte distributions; random data does not.
  * pairwise diff of the two GAME saves (first/last differing offset,
    differing-byte count) - two saves from the same player should share a
    large identical prefix if the file is plaintext with a few changed
    fields, and share nothing if a per-save keystream is applied.
"""
import os
import math
import hashlib
import collections

ROOT = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
READ_CAP = 4 * 1024 * 1024


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = float(len(b))
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def block_stats(b, bs=16):
    n = len(b) // bs
    if not n:
        return 0, 0, 0.0
    seen = set()
    for i in range(n):
        seen.add(b[i * bs:(i + 1) * bs])
    return n, len(seen), len(seen) / float(n)


def nibble_bias(b):
    """Rough structured-vs-random check: how far is the byte histogram from
    uniform over the 256 values, in normalised chi-square terms."""
    if len(b) < 4096:
        return 0.0
    c = collections.Counter(b)
    exp = len(b) / 256.0
    chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    # chi2 with 255 dof; mean 255, sd sqrt(2*255)
    return (chi - 255.0) / math.sqrt(2.0 * 255.0)


print('=== inventory ===')
blobs = {}
for dirpath, dirs, files in os.walk(ROOT):
    for f in sorted(files):
        p = os.path.join(dirpath, f)
        rel = os.path.relpath(p, ROOT)
        sz = os.path.getsize(p)
        with open(p, 'rb') as fh:
            data = fh.read(READ_CAP)
        n, uniq, frac = block_stats(data[:256 * 1024])
        blobs[rel] = data
        print('%-46s size=%-8d sha1=%s ent=%.4f ent4k=%.4f '
              'blk16=%d/%d (%.3f) chi2z=%+.1f'
              % (rel, sz, hashlib.sha1(data[:READ_CAP]).hexdigest()[:12],
                 entropy(data), entropy(data[:4096]),
                 uniq, n, frac, nibble_bias(data[:262144])))

print('\n=== header bytes ===')
for rel in sorted(blobs):
    b = blobs[rel][:48]
    print('%-46s %s' % (rel, ' '.join('%02X' % x for x in b)))

print('\n=== known magics present anywhere in file (first 64 KiB) ===')
MAG = {'zlib_default': b'\x78\x9c', 'zlib_best': b'\x78\xda',
       'zlib_none': b'\x78\x01', 'gzip': b'\x1f\x8b\x08',
       'lzma_alone': b'\x5d\x00\x00', 'PARAM.SFO': b'\x00PSF',
       'pkzip': b'PK\x03\x04', 'utf8_json': b'{"', 'ascii_%': b'%s'}
for rel in sorted(blobs):
    d = blobs[rel][:65536]
    hits = [k for k, m in MAG.items() if m in d]
    print('%-46s %s' % (rel, hits or '-'))

# ---- pairwise diff of the GAME saves -----------------------------------
games = sorted(k for k in blobs if 'SN5GAME' in k and 'DATA' in k.upper())
if len(games) >= 2:
    print('\n=== pairwise diff ===')
    a, b = blobs[games[0]], blobs[games[1]]
    m = min(len(a), len(b))
    first = last = None
    diff = 0
    for i in range(m):
        if a[i] != b[i]:
            diff += 1
            if first is None:
                first = i
            last = i
    print('  %s (%d) vs %s (%d)' % (games[0], len(a), games[1], len(b)))
    print('  compared %d bytes: %d differ (%.2f%%)' % (m, diff, 100.0 * diff / m))
    print('  first diff at 0x%X, last at 0x%X' % (first or -1, last or -1))
    if first is not None and first > 0:
        print('  identical prefix length = 0x%X (%d bytes)' % (first, first))
    # 16-byte block overlap
    n, ua, _ = block_stats(a)
    n, ub, _ = block_stats(b)
    sa, sb = set(), set()
    for i in range(len(a) // 16):
        sa.add(a[i * 16:i * 16 + 16])
    for i in range(len(b) // 16):
        sb.add(b[i * 16:i * 16 + 16])
    print('  shared distinct 16B blocks: %d (of %d / %d)'
          % (len(sa & sb), len(sa), len(sb)))
else:
    print('\n=== no two DATA.BIN files found; listing candidates ===')
    for k in sorted(blobs):
        if 'GAME' in k.upper() or 'DATA' in k.upper():
            print('  ', k, len(blobs[k]))
print('DONE')
