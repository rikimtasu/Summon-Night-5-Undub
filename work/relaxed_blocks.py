"""Relaxed whole-RAM script-block census + landlady pool ownership hunt.

- Magic scan with generous caps (previous 0xC0000/0x40000 may hide blocks).
- Raw CALL195 (0x0074,195) / CALL214 (0x0074,214) pattern counts per block.
- For NPJH_4: inspect the 大家さん string region, find pool start, and test
  every magic header for a pool that begins at that region.
"""
import struct, sys, os, collections
import zstandard

sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\\PSP\\PPSSPP_STATE'
STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
STATES = [
    ('ULUS10656_1.01_0.ppst', 'usa'),
    ('ULUS10656_1.01_1.ppst', 'usa'),
    ('ULUS10656_1.01_2.ppst', 'usa'),
    ('ULUS10656_1.01_3.ppst', 'usa'),
    ('ULUS10656_1.01_4.ppst', 'usa'),
    ('NPJH50696_1.01_0.ppst', 'jp'),
    ('NPJH50696_1.01_1.ppst', 'jp'),
    ('NPJH50696_1.01_4.ppst', 'jp'),
]
M1 = struct.pack('<I', 0x10000201)
M2 = struct.pack('<I', 0x10000002)
PAT195 = struct.pack('<HH', 0x0074, 195)
PAT214 = struct.pack('<HH', 0x0074, 214)


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory'
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


def count(blob, pat, lo=0, hi=None):
    hi = len(blob) if hi is None else hi
    n = 0
    s = lo
    while True:
        i = blob.find(pat, s, hi)
        if i < 0:
            break
        n += 1
        s = i + 4
    return n


def headers_relaxed(ram, size_cap=0x600000, c10_cap=0x100000):
    out = []
    s = 0
    while True:
        i = ram.find(M1, s)
        if i < 0:
            break
        s = i + 1
        if ram[i + 4:i + 8] != M2:
            continue
        size = struct.unpack('<I', ram[i + 8:i + 12])[0]
        c10 = struct.unpack('<I', ram[i + 16:i + 20])[0]
        if size & 1 or not (c10 * 2 <= size <= size_cap):
            continue
        if not (64 < c10 < c10_cap):
            continue
        out.append((i, size, c10))
    return out


print('=== relaxed block census (all states) ===', flush=True)
for name, tag in STATES:
    ram = extract_ram(os.path.join(STATE, name))
    hs = headers_relaxed(ram)
    print('%-24s (%s): %d block(s)' % (name, tag, len(hs)))
    for (o, size, c10) in hs:
        blk = ram[o:o + size]
        n195 = count(blk, PAT195)
        n214 = count(blk, PAT214)
        print('   base=0x%X size=%-8d c10=%-7d raw195=%-5d raw214=%d'
              % (o, size, c10, n195, n214), flush=True)
    del ram

print()
print('=== NPJH_4 landlady region ===', flush=True)
ram4 = extract_ram(os.path.join(STATE, 'NPJH50696_1.01_4.ppst'))
needle = '\u5927\u5bb6\u3055\u3093'.encode('utf-8')
hits = []
s = 0
while True:
    i = ram4.find(needle, s)
    if i < 0:
        break
    hits.append(i)
    s = i + 1
print('daisann hits:', len(hits), ['0x%X' % h for h in hits[:6]], '...',
      ['0x%X' % h for h in hits[-3:]])
lo, hi = min(hits), max(hits)
print('region 0x%X..0x%X span %d' % (lo, hi, hi - lo + len(needle)))

# structure: how are strings delimited in this region?
print('hex around first hit:')
print(' ', ram4[hits[0] - 48:hits[0] + 96].hex())
# count NUL density in region
seg = ram4[lo - 0x400:hi + 0x400]
print('NULs in +-1KB window: %d / %d' % (seg.count(0), len(seg)))

# find the earliest string start in the cluster: walk back over NUL-separated runs
def pool_bounds(ram, pos, window=0x20000):
    """walk back to find start of a NUL-separated string region"""
    start = pos
    p = pos
    lim = max(0, pos - window)
    while p > lim:
        if ram[p - 1] == 0 and ram[p] != 0:
            # start of a string; keep walking while region is NUL-delimited
            start = p
            p -= 1
            while p > lim and ram[p] != 0:
                p -= 1
        else:
            p -= 1
    return start

b0 = pool_bounds(ram4, hits[0])
print('approx pool start (string-run walk): 0x%X' % b0)

# test every magic header in RAM4: does its pool region cover the landlady region?
print()
print('magic headers in NPJH_4 and their pool extents:')
for (o, size, c10) in headers_relaxed(ram4):
    pool = o + c10 * 2
    pend = o + size
    covers = pool <= lo and hi + len(needle) <= pend
    print('   base=0x%X size=%d c10=%d pool=0x%X..0x%X covers_landlady=%s'
          % (o, size, c10, pool, pend, covers))
    # also: are the strings in the pool a dense run (printable ratio)?
    if pool < len(ram4):
        seg = ram4[pool:min(pend, pool + 0x4000)]
        printable = sum(1 for b in seg if 32 <= b < 127 or b >= 0x80)
        print('        first 16KB of pool printable ratio: %.2f' % (printable / len(seg)))
print('DONE', flush=True)
