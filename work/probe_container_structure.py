# -*- coding: utf-8 -*-
"""Structure probe for the script container (02.DAT), offline.

probe_script_containers.py showed: no block header, no plaintext dialogue, and
entropy ~5.5 (compression-like, not encryption-like ~8).  So the story script IS
in here, just packed.  Before committing to EBOOT RE to find the expander, try
the cheap wins:

  1. dump the file header and a per-chunk entropy profile to expose an index
     table or per-chapter stream boundaries;
  2. try standard decompressors (zlib / raw deflate / lzma) at a coarse offset
     grid, in case the packer used a stock codec;
  3. try the known dialogue in other encodings (UTF-16LE, cp932) in case only
     the *text* is transformed and the block is otherwise clear.

A hit on any of these means every chapter can be dumped offline, no game boot.

Run:  python probe_container_structure.py
"""
import os
import struct
import sys
import zlib
import lzma

WORK = r'D:\Documents\Default Project\work'
JP02 = os.path.join(WORK, 'JP', 'PSP_GAME', 'USRDIR', '02.DAT')
USA02 = os.path.join(WORK, 'USA', 'PSP_GAME', 'USRDIR', '02.DAT')

PROBES = [b'It was a great war',
          b'Long, long ago']


def entropy(sample):
    import collections
    import math
    if not sample:
        return 0.0
    c = collections.Counter(sample)
    n = len(sample)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def header(path, n=256):
    with open(path, 'rb') as f:
        return f.read(n)


def chunk_entropy(path, step=1 << 20):
    out = []
    with open(path, 'rb') as f:
        i = 0
        while True:
            b = f.read(step)
            if not b:
                break
            out.append(entropy(b))
            i += 1
    return out


def try_decompressors(path, grid=4096, limit=64 << 20):
    """Coarse sweep for stock compressed streams near the start of the file."""
    hits = []
    with open(path, 'rb') as f:
        blob = f.read(limit)
    for off in range(0, len(blob) - 64, grid):
        for name, fn in (
            ('zlib', lambda b: zlib.decompress(b)),
            ('deflate', lambda b: zlib.decompress(b, -15)),
            ('lzma', lambda b: lzma.decompress(b)),
        ):
            try:
                out = fn(blob[off:off + 1 << 20])
            except Exception:
                continue
            if len(out) > 4096:
                hits.append((off, name, len(out)))
                if len(hits) >= 20:
                    return hits
    return hits


def text_encodings(path, limit=1 << 28):
    """Known dialogue in other encodings (UTF-16LE / cp932)."""
    out = []
    with open(path, 'rb') as f:
        blob = f.read(limit)
    for p in PROBES:
        for enc in ('utf-16-le', 'shift_jis', 'utf-16-be'):
            raw = p.decode('ascii').encode(enc, 'ignore')
            o = blob.find(raw)
            if o >= 0:
                out.append((p.decode('ascii'), enc, o))
    return out


def show_u32(blob, base=0, count=16):
    vals = struct.unpack_from('<%dI' % count, blob, base)
    return ' '.join('0x%08X' % v for v in vals)


def main():
    for tag, path in (('jp/02.DAT', JP02), ('usa/02.DAT', USA02)):
        if not os.path.isfile(path):
            print('%s MISSING' % tag)
            continue
        size = os.path.getsize(path)
        print('=== %s (%d bytes) ===' % (tag, size))
        head = header(path)
        print('  first 64 bytes : %s' % head[:64].hex())
        print('  first u32s     : %s' % show_u32(head, 0, 16))
        print('  ascii head     : %r' % head[:64])
        prof = chunk_entropy(path)
        print('  entropy/1MiB   : %s' %
              ' '.join('%.2f' % e for e in prof[:32]))
        print('  (low-entropy chunks = text/script; high = other assets)')
        print('  text encodings : %s' % (text_encodings(path) or 'none'))
        hits = try_decompressors(path)
        print('  stock streams  : %s' % (hits or 'none in first 64 MiB'))
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
