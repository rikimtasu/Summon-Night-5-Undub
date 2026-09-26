"""Full structural scan: find EVERY resident script block in all SN5 save states.

Magic sweep (0x10000201/0x10000002) + chapter_voice_census.parse_block for
validation: header invariants, clean disasm landing, and >=5 dialogue lines
counted with the block's OWN calibrated text call (dialect()), not hardcoded
CALL195 - so non-prologue dialects (e.g. ch2 textCALL=208) are found too.
Then census voice sites by form + preview pool strings (UTF-8).
Dedupes identical (c10, size) blocks across states.
"""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths
import chapter_voice_census as C

STATE = paths.state_dir()
if not STATE:
    raise SystemExit('SN5_PPSSPP_MEMSTICK is not set, so the PPSSPP_STATE '
                     'directory is unknown; see work/paths.py')
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


# Voice/text classification lives in chapter_voice_census (dialect-calibrated
# census_voice + parse_block); the hardcoded CALL195/CALL214 census that used
# to sit here missed every non-prologue dialect block (ch2 54606, 49220/41244).


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
    """yield a census block dict for every structurally valid script block.
    Header invariants (from known JP/USA prologue blocks):
      u32@+0 == 0x10000201, u32@+4 == 0x10000002, u32@+8 == block size (even,
      >= c10*2), u32@+16 == c10; validation + dialect calibration all inside
      chapter_voice_census.parse_block."""
    hits = []
    n = len(ram)
    magic = struct.pack('<I', 0x10000201)
    start = 0
    while True:
        o = ram.find(magic, start, n - 32)
        if o < 0:
            break
        start = o + 4
        blk = C.parse_block(ram, o)
        if blk is None:
            continue
        hits.append(blk)
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
    for blk in hits:
        c = blk['census']
        const = sum(v for (f, _), v in c.items() if f == 'const')
        f2 = sum(v for (f, _), v in c.items() if f == 'f2')
        pair = sum(v for (f, _), v in c.items() if f == 'pair')
        print('   base=0x%08X c10=%-6d lines=%-5d const=%-4d f2=%-3d pair=%-4d textCALL=%-3d voiceCALL=%-3d'
              % (blk['off'], blk['c10'], len(blk['lines']), const, f2, pair,
                 blk['text_call'], blk['voice_call']), flush=True)
        for t in preview_strings(blk['data'], blk['c10']):
            print('        str: %s' % t, flush=True)
        seen_global[(tag, blk['c10'])].append(name)
    del ram

print()
print('=== distinct (version, c10) script contexts across all states ===')
for k, v in sorted(seen_global.items()):
    print('  %s c10=%-6d in %s' % (k[0], k[1], v))
print('DONE', flush=True)
