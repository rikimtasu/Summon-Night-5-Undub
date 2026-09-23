"""Extract RAM from all SN5 save states, locate the script block in each,
census CALL195/CALL214 by form, and check whether the captured scenes
(war narration / landlady) belong to the known prologue block."""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
STATES = [
    ('ULUS10656_1.01_0.ppst', 'usa', 0),
    ('ULUS10656_1.01_1.ppst', 'usa', 1),
    ('ULUS10656_1.01_2.ppst', 'usa', 2),
    ('ULUS10656_1.01_3.ppst', 'usa', 3),
    ('ULUS10656_1.01_4.ppst', 'usa', 4),
    ('NPJH50696_1.01_0.ppst', 'jp', 0),
    ('NPJH50696_1.01_1.ppst', 'jp', 1),
    ('NPJH50696_1.01_4.ppst', 'jp', 4),
]
BASE = {'usa': 0xD68000, 'jp': 0xD2D000}   # known prologue block addrs - 0x08000000


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
    other = []
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
                else:
                    other.append(t[0])
    return c, n195, other


def preview_strings(blk, c10, n=3):
    out = []
    p = c10 * 2
    while p < len(blk) and len(out) < n:
        e = blk.find(b'\x00', p)
        if e < 0:
            break
        s = blk[p:e]
        if len(s) >= 4:
            for enc in ('utf-8', 'shift_jis', 'latin-1'):
                try:
                    txt = s.decode(enc)
                    if any(ch.isalpha() for ch in txt) or any(ord(ch) > 0x3000 for ch in txt):
                        out.append((enc, txt[:64]))
                        break
                except Exception:
                    continue
        p = e + 1
    return out


def try_block(ram, base, tag):
    """read header at base; return (c10, tokens, pool_preview) or None"""
    if base + 32 > len(ram):
        return None
    c10 = struct.unpack('<I', ram[base + 16:base + 20])[0]
    if not (16 < c10 < 0x40000) or c10 * 2 > 0x80000:
        return None
    blk = ram[base:base + c10 * 2 + 4096]
    # clean-landing validation
    tokens = disasm(blk[:c10 * 2], 12)
    if not tokens:
        return None
    if tokens[-1][0] + 2 > c10 * 2 + 4:   # last token must end near c10*2
        return None
    return c10, tokens, blk


print('=== state census ===')
blocks = {}
for name, tag, slot in STATES:
    p = os.path.join(STATE, name)
    try:
        ram = extract_ram(p)
    except Exception as e:
        print('%-24s EXTRACT FAIL: %s' % (name, e))
        continue
    base = BASE[tag]
    res = try_block(ram, base, tag)
    if res is None:
        print('%-24s block @%s: no valid header' % (name, hex(base)))
        continue
    c10, tokens, blk = res
    c, n195, other = census(tokens)
    const = sum(v for (f, _), v in c.items() if f == 'const')
    f2 = sum(v for (f, _), v in c.items() if f == 'f2')
    pair = sum(v for (f, _), v in c.items() if f == 'pair')
    prev = preview_strings(blk, c10)
    key = (tag, c10)
    blocks.setdefault(key, []).append(name)
    print('%-24s base=%s c10=%-6d lines=%-5d const=%-4d f2=%-3d pair=%-4d other=%d'
          % (name, hex(base), c10, n195, const, f2, pair, len(other)))
    for enc, t in prev:
        print('      str[%s]: %s' % (enc, t))

# cross-check: scenes in known prologue blocks
print()
print('=== scene membership ===')
usa = open(r'D:\Documents\Default Project\work\psp_ram_usa3.bin', 'rb').read()
jp = open(r'D:\Documents\Default Project\work\psp_ram_jp.bin', 'rb').read()
ub = usa[0xD68000:0xD68000 + 158152]
jb = jp[0xD2D000:0xD2D000 + 180224]
for probe in (b'great war', b'great War', b'Great war'):
    print('USA prologue block contains %-12r: %s' % (probe, probe in ub))
for probe in (b'\x90\xa8\x82\xbf', b'\xe5\xa4\xa7\xe5\xa6\xb6'):  # SJIS 大家 / UTF-8 大家
    print('JP prologue block contains %-14r: %s' % (probe, probe in jb))
# utf-8 大家さん = e5 a4 a7 e5 a6 b6 e3 82 b5 e3 83 b3
print('JP prologue block contains utf8 大家さん:',
      b'\xe5\xa4\xa7\xe5\xa6\xb6\xe3\x82\xb5\xe3\x83\xb3' in jb)
print('JP prologue block contains sjis 大家:',
      b'\x90\xa8\x82\xbf' in jb)
