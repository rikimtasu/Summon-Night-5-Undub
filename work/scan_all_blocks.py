"""Full structural scan: find EVERY resident script block in all SN5 save states.

For each 16-aligned offset o in RAM:
  c10 = u32@o+16 ; require 512 < c10 < 0x40000 (rare by chance),
  disasm(ram[o:o+c10*2], 12) must land cleanly, >=5 CALL195 dialogue lines.
Then census CALL214 sites by form + preview pool strings (UTF-8).
Dedupes identical (c10, size) blocks across states.
"""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

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


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory'
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


def census(tokens):
    c = collections.Counter()
    n195 = 0
    for k, t in enumerate(tokens):
        if t[1] == 52 and t[2] == 1 and t[4]:
            if t[4][0] == 195:
                n195 += 1
            elif t[4][0] == 214:
                p = tokens[k - 1] if k >= 1 else None
                if p and p[1] == 50 and p[2] == 10 and p[4]:
                    c[('const', p[4][0])] += 1
                elif p and p[1] == 50 and p[2] == 11:
                    c[('f2', p[3] - 1)] += 1
                elif p and p[1] == 50 and p[2] == 4 and p[4]:
                    c[('pair', p[4][0])] += 1
    return c, n195


def preview_strings(blk, c10, n=3):
    out = []
    p = c10 * 2
    while p < len(blk) and len(out) < n:
        e = blk.find(b'\x00', p)
        if e < 0:
            break
        s = blk[p:e]
        if len(s) >= 6:
            try:
                txt = s.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    txt = s.decode('shift_jis')
                except UnicodeDecodeError:
                    txt = None
            if txt and any(ch.isalpha() or ord(ch) > 0x2FFF for ch in txt):
                out.append(txt[:70])
        p = e + 1
    return out


def scan(ram):
    """yield (base, c10, tokens) for every structurally valid script block.
    Header invariants (from known JP/USA prologue blocks):
      u32@+0 == 0x10000201, u32@+4 == 0x10000002, u32@+8 == block size (even,
      >= c10*2), u32@+16 == c10; token stream starts at byte 24 (unit 12)."""
    hits = []
    n = len(ram)
    magic = struct.pack('<I', 0x10000201)
    start = 0
    while True:
        o = ram.find(magic, start, n - 32)
        if o < 0:
            break
        start = o + 4
        if struct.unpack('<I', ram[o + 4:o + 8])[0] != 0x10000002:
            continue
        size = struct.unpack('<I', ram[o + 8:o + 12])[0]
        c10 = struct.unpack('<I', ram[o + 16:o + 20])[0]
        if size & 1 or not (c10 * 2 <= size <= 0xC0000):
            continue
        if not (512 < c10 < 0x40000):
            continue
        end = o + c10 * 2
        if end > n:
            continue
        try:
            toks = disasm(ram[o:end], 12)
        except (IndexError, struct.error):
            continue
        if not toks or not (c10 - 4 <= toks[-1][0] + 1 <= c10):
            continue
        c, n195 = census(toks)
        if n195 < 5:
            continue
        hits.append((o, c10, n195, c))
    return hits


seen_global = collections.defaultdict(list)   # (tag,c10) -> [state names]
for name, tag in STATES:
    try:
        ram = extract_ram(os.path.join(STATE, name))
    except Exception as e:
        print('%-24s EXTRACT FAIL: %s' % (name, e), flush=True)
        continue
    hits = scan(ram)
    print('%-24s: %d script block(s)' % (name, len(hits)), flush=True)
    for (o, c10, n195, c) in hits:
        const = sum(v for (f, _), v in c.items() if f == 'const')
        f2 = sum(v for (f, _), v in c.items() if f == 'f2')
        pair = sum(v for (f, _), v in c.items() if f == 'pair')
        print('   base=0x%08X c10=%-6d lines=%-5d const=%-4d f2=%-3d pair=%-4d'
              % (o, c10, n195, const, f2, pair), flush=True)
        for t in preview_strings(ram[o:o + c10 * 2 + 8192], c10):
            print('        str: %s' % t, flush=True)
        seen_global[(tag, c10)].append(name)
    del ram

print()
print('=== distinct (version, c10) script contexts across all states ===')
for k, v in sorted(seen_global.items()):
    print('  %s c10=%-6d in %s' % (k[0], k[1], v))
print('DONE', flush=True)
