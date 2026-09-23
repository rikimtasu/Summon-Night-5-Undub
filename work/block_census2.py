"""Per-block opcode census for every script block resident in every SN5 state.

Fixes the op52/f1=1 encoding: token u16 = op | f1<<6 | f2<<12, so op52,f1=1
is 0x0074 (0x0034 would be f1=0). For each block: CALL target histogram
(op52,f1=1) and voice sites (CALL214 targets 214) by arg form.
"""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
STATES = [
    ('ULUS10656_1.01_0.ppst', 'usa'),
    ('ULUS10656_1.01_3.ppst', 'usa'),
    ('ULUS10656_1.01_4.ppst', 'usa'),
    ('NPJH50696_1.01_0.ppst', 'jp'),
    ('NPJH50696_1.01_4.ppst', 'jp'),
]

CALL195 = struct.pack('<HH', 52 | (1 << 6), 195)
CALL214 = struct.pack('<HH', 52 | (1 << 6), 214)


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory'
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


def headers(ram):
    out = []
    m1 = struct.pack('<I', 0x10000201)
    s = 0
    while True:
        i = ram.find(m1, s)
        if i < 0:
            break
        s = i + 1
        if ram[i + 4:i + 8] != struct.pack('<I', 0x10000002):
            continue
        size = struct.unpack('<I', ram[i + 8:i + 12])[0]
        c10 = struct.unpack('<I', ram[i + 16:i + 20])[0]
        if c10 * 2 <= size <= 0xC0000 and 512 < c10 < 0x40000 and not (size & 1):
            out.append((i, size, c10))
    return out


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


def call_hist(tokens):
    """histogram of op52 f1=1 call targets"""
    h = collections.Counter()
    for t in tokens:
        if t[1] == 52 and t[2] == 1 and t[4]:
            h[t[4][0]] += 1
    return h


def voice_sites(tokens):
    c = collections.Counter()
    for k, t in enumerate(tokens):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 214:
            p = tokens[k - 1] if k >= 1 else None
            if p and p[1] == 50 and p[2] == 10 and p[4]:
                c[('const', p[4][0])] += 1
            elif p and p[1] == 50 and p[2] == 11:
                c[('f2', p[3] - 1)] += 1
            elif p and p[1] == 50 and p[2] == 4 and p[4]:
                c[('pair', p[4][0])] += 1
            else:
                c['other'] += 1
    return c


for name, tag in STATES:
    ram = extract_ram(os.path.join(STATE, name))
    print('=== %s (%s) ===' % (name, tag))
    for (o, size, c10) in headers(ram):
        blk = ram[o:o + size]
        tokarea = blk[:c10 * 2]
        n195raw = count(tokarea, CALL195)
        n214raw = count(tokarea, CALL214)
        try:
            toks = disasm(tokarea, 12)
            land = '%s<=%d<=%s' % (c10 - 4, toks[-1][0] + 1, c10) if toks else 'none'
        except Exception as e:
            toks = []
            land = 'ERR %s' % e
        h = call_hist(toks)
        vs = voice_sites(toks)
        print('  base=0x%X size=%d c10=%d  raw195=%d raw214=%d tokens=%d land=%s'
              % (o, size, c10, n195raw, n214raw, len(toks), land))
        print('    call targets:', dict(sorted(h.items(), key=lambda kv: -kv[1])[:12]))
        print('    voice sites:', dict(vs))
        # raw-pattern voice forms in whole block (detect forms beyond disasm)
        n214pool = count(blk, CALL214, c10 * 2)
        print('    CALL214 pattern in pool region:', n214pool)
    del ram
print('DONE', flush=True)
