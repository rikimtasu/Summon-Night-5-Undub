# -*- coding: utf-8 -*-
"""Hunt the compressed form of a loaded story block inside a save-state RAM.

If the loader keeps the compressed bytes in RAM, a known input/output pair
(compressed -> the block we can already read) lets us identify the algorithm
offline, which would unlock full 02.DAT enumeration without more captures.

Tries, at every plausible offset in RAM: zlib/gzip/LZMA/raw-deflate, plus a
generic LZ77-style back-reference search for the block's first tokens.
"""
import os
import struct
import sys
import zlib
import zstandard

sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram, headers, STATE

STATE_DIR = STATE
ram = extract_ram(os.path.join(STATE_DIR, 'ULUS10656_1.01_0.ppst'))
print('RAM: %d bytes' % len(ram))

# the story block we want to explain
blk = None
for (o, size, c10) in headers(ram):
    if c10 > 10000:
        blk = ram[o:o + size]
        print('target block: base=0x%X size=%d c10=%d' % (o, size, c10))
        break
if blk is None:
    raise SystemExit('no story block found')
head = blk[:24]
print('block head:', head.hex())

MAGICS = {
    'zlib_9c': b'\x78\x9c', 'zlib_01': b'\x78\x01', 'zlib_da': b'\x78\xda',
    'zlib_5e': b'\x78\x5e', 'gzip': b'\x1f\x8b', 'lzma': b'\x5d\x00\x00',
    'xz': b'\xfd7zXZ', 'bzip2': b'BZh', 'zstd': b'\x28\xb5\x2f\xfd',
    'lz4': b'\x04\x22\x4d\x18',
}

print('\n=== scanning RAM for compression headers ===')
found_any = False
for name, magic in MAGICS.items():
    s = 0
    hits = []
    while len(hits) < 40:
        i = ram.find(magic, s)
        if i < 0:
            break
        hits.append(i)
        s = i + 1
    if hits:
        found_any = True
        print('  %-8s %d hit(s): %s' % (name, len(hits), [hex(x) for x in hits[:8]]))
        for i in hits[:8]:
            blob = ram[i:i + min(len(blk) * 2, 400000)]
            for fn, dec in (('zlib', lambda b: zlib.decompress(b)),
                            ('raw-deflate', lambda b: zlib.decompress(b, -15)),
                            ('gzip', lambda b: zlib.decompress(b, 31)),
                            ('lzma', lambda b: __import__('lzma').decompress(b))):
                try:
                    out = dec(blob)
                except Exception:
                    continue
                if len(out) > 64:
                    print('      %s@0x%X -> %d bytes, head=%s' % (fn, i, len(out), out[:16].hex()))
                    if out[:4] == head[:4]:
                        print('      *** MATCHES BLOCK HEADER ***')
                    found_any = True
if not found_any:
    print('  no standard compression header found in RAM')

# does the compressed data perhaps live in the VRAM-mirrored / stack region?
# Instead, look for the block's 24-byte header appearing anywhere else in RAM
h = struct.pack('<I', 0x10000201)
print('\n=== block magic occurrences in RAM ===')
s = 0
occ = []
while True:
    i = ram.find(h, s)
    if i < 0:
        break
    occ.append(i)
    s = i + 1
for i in occ:
    size = struct.unpack('<I', ram[i + 8:i + 12])[0]
    c10 = struct.unpack('<I', ram[i + 16:i + 20])[0]
    print('  0x%X size=%d c10=%d' % (i, size, c10))
print('DONE', flush=True)
