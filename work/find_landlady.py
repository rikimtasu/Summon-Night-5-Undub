"""1) locate the landlady script block in NPJH_4 RAM via its strings,
   census its voice sites; 2) locate prologue block in ULUS_3;
3) re-parse 02.DAT entry table with es=32 and test (offset,size) partition."""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(d[176:176 + esize], max_output_size=usize + 16)
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


def find_strings(ram, probes):
    out = []
    for name, b in probes:
        s = 0
        while True:
            i = ram.find(b, s)
            if i < 0:
                break
            out.append((name, i))
            s = i + 1
    return out


def locate_block(ram, spos, maxdelta=600000):
    """given a string position inside the pool, find block base candidates:
    base 16-aligned, c10=u32@base+16, delta = spos-base-c10*2 in [0,maxdelta),
    token stream decends cleanly to c10*2 with >=5 dialogue lines."""
    hits = []
    lo = max(0, spos - 0x90000 - maxdelta)
    for o in range(spos & ~15, lo, -16):
        c10 = struct.unpack('<I', ram[o + 16:o + 20])[0]
        if not (512 < c10 < 0x40000):
            continue
        delta = spos - o - c10 * 2
        if not (0 <= delta < maxdelta):
            continue
        blk = ram[o:o + c10 * 2]
        if len(blk) < c10 * 2 or len(blk) & 1:
            continue
        try:
            toks = disasm(blk, 12)
        except (IndexError, struct.error):
            continue
        if not toks or not (c10 - 4 <= toks[-1][0] + 1 <= c10):
            continue
        c, n195 = census(toks)
        if n195 < 5:
            continue
        hits.append((o, c10, n195, c))
        if len(hits) >= 4:
            break
    return hits


print('=== NPJH_4 landlady block ===')
ram4 = extract_ram(os.path.join(STATE, 'NPJH50696_1.01_4.ppst'))
probes = [('landlady', b'\xe5\xa4\xa7\xe5\xa6\xb6\xe3\x82\xb5\xe3\x83\xb3'),   # 大家さん
          ('arca', b'\xe3\x82\xa2\xe3\x83\xab\xe3\x82\xab'),                    # アルカ
          ('shopp0', b'\xe3\x81\x84\xe3\x82\x89\xe3\x81\xa3\xe3\x81\x97\xe3\x82\x87')]  # いらっ
sp = find_strings(ram4, probes)
print('string hits:', collections.Counter(n for n, _ in sp), 'total', len(sp))
seen = set()
for name, pos in sp:
    res = locate_block(ram4, pos)
    for (o, c10, n195, c) in res:
        if (o, c10) in seen:
            continue
        seen.add((o, c10))
        const = sum(v for (f, _), v in c.items() if f == 'const')
        f2 = sum(v for (f, _), v in c.items() if f == 'f2')
        pair = sum(v for (f, _), v in c.items() if f == 'pair')
        print('  base=0x%X c10=%d lines=%d const=%d f2=%d pair=%d (via %s @0x%X)'
              % (o, c10, n195, const, f2, pair, name, pos))
    if seen:
        break

print()
print('=== ULUS_3 war-narration state: locate prologue block ===')
ram3 = extract_ram(os.path.join(STATE, 'ULUS10656_1.01_3.ppst'))
sp3 = find_strings(ram3, [('war', b'great war'), ('welcome', b'Welcome! How may')])
print('string hits:', collections.Counter(n for n, _ in sp3))
seen3 = set()
for name, pos in sp3:
    for (o, c10, n195, c) in locate_block(ram3, pos):
        if (o, c10) in seen3:
            continue
        seen3.add((o, c10))
        const = sum(v for (f, _), v in c.items() if f == 'const')
        pair = sum(v for (f, _), v in c.items() if f == 'pair')
        print('  base=0x%X c10=%d lines=%d const=%d pair=%d (via %s)'
              % (o, c10, n195, const, pair, name))

print()
print('=== 02.DAT entry table es=32 partition test ===')
usa_iso = r'D:\Documents\Default Project\Summon Night 5 (USA).iso'
with open(usa_iso, 'rb') as f:
    f.seek(328826880)
    hdr = f.read(68)
    cnt = 24221
    es = 32
    f.seek(328826880 + 70)
    tbl = f.read(cnt * es)
print('header:', struct.unpack('<17I', hdr))
rows = [struct.unpack('<8I', tbl[i * es:(i + 1) * es]) for i in range(min(6, cnt))]
for i, r in enumerate(rows):
    print('  entry%d:' % i, r)
# field stats + partition search: (a,b): sort by a, check sorted a + b == next a
import itertools
stats = []
for a in range(8):
    va = [r[a] for r in rows[:]]  # first rows only for speed test
vals = [struct.unpack('<8I', tbl[i * es:(i + 1) * es]) for i in range(cnt)]
for a in range(8):
    for b in range(8):
        if a == b:
            continue
        seq = sorted(range(cnt), key=lambda i: vals[i][a])
        # take first 200 sorted; check vals[i][a] + vals[i][b] == next vals[a]
        ok = 0
        test = seq[:400]
        for j in range(len(test) - 1):
            i, j2 = test[j], test[j + 1]
            if vals[i][a] + vals[i][b] == vals[j2][a]:
                ok += 1
        if ok > 100:
            stats.append((a, b, ok))
print('partition-consistent (field_a + field_b == next a) over first 400 sorted:',
      stats if stats else 'NONE')
# also: which fields are monotonic in file order?
for a in range(8):
    mono = sum(1 for i in range(cnt - 1) if vals[i][a] <= vals[i + 1][a])
    print('  field%d file-order nondecreasing: %d/%d  min=%d max=%d'
          % (a, mono, cnt - 1, min(v[a] for v in vals), max(v[a] for v in vals)))
