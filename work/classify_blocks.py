"""Classify each block's text/voice function ids without hardcoding, and
preview its string pool.

Calibration facts (from the known prologue block):
  text  function = call target with most op50 f1=5 (string-index) pushes
  voice function = call target with most op50 f1=4 (pair-id) pushes
Verify on both JP blocks, then apply to the post-prologue block.
"""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
M1 = struct.pack('<I', 0x10000201)
M2 = struct.pack('<I', 0x10000002)


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
        if size & 1 or not (c10 * 2 <= size <= 0x600000 and 64 < c10 < 0x100000):
            continue
        out.append((i, size, c10))
    return out


def classify(tok):
    """return (textfunc, voicefunc, stats)"""
    f5 = collections.Counter()   # text: f1=5 string-index pushes
    f4 = collections.Counter()   # voice: f1=4 pair pushes
    f10 = collections.Counter()
    f11 = collections.Counter()
    allcalls = collections.Counter()
    for k in range(1, len(tok)):
        t = tok[k]
        if not (t[1] == 52 and t[2] == 1 and t[4]):
            continue
        tgt = t[4][0]
        allcalls[tgt] += 1
        p = tok[k - 1]
        if p[1] != 50:
            continue
        if p[2] == 5:
            f5[tgt] += 1
        elif p[2] == 4:
            f4[tgt] += 1
        elif p[2] == 10:
            f10[tgt] += 1
        elif p[2] == 11:
            f11[tgt] += 1
    text = f5.most_common(1)[0][0] if f5 else None
    voice = f4.most_common(1)[0][0] if f4 else None
    return text, voice, allcalls, f5, f4, f10, f11


def preview(ram, base, size, c10, n=6):
    out = []
    p = c10 * 2
    end = base + size
    while p < end and len(out) < n:
        e = ram.find(b'\x00', base + p, end)
        if e < 0:
            break
        s = ram[base + p:e]
        p = e - base + 1
        if len(s) >= 6:
            try:
                txt = s.decode('utf-8')
            except UnicodeDecodeError:
                continue
            if any(ch.isalpha() or ord(ch) > 0x2FFF for ch in txt):
                out.append(txt[:60])
    return out


CASES = [
    ('NPJH50696_1.01_0.ppst', 'jp', 'prologue?'),
    ('ULUS10656_1.01_0.ppst', 'usa', 'prologue?'),
    ('NPJH50696_1.01_4.ppst', 'jp', 'landlady?'),
]
for name, tag, expect in CASES:
    ram = extract_ram(os.path.join(STATE, name))
    print('=== %s (%s) expect %s ===' % (name, tag, expect))
    for (o, size, c10) in headers(ram):
        tok = disasm(ram[o:o + c10 * 2], 12)
        if not tok or not (c10 - 4 <= tok[-1][0] + 1 <= c10):
            print('  base=0x%X c10=%d LANDING FAIL' % (o, c10))
            continue
        text, voice, allc, f5, f4, f10, f11 = classify(tok)
        print('  base=0x%X size=%d c10=%d' % (o, size, c10))
        print('     textfunc=%s (f5=%d)  voicefunc=%s (f4 pair=%d)'
              % (text, f5[text] if text else 0, voice, f4[voice] if voice else 0))
        if voice is not None:
            nv = f4[voice] + f10[voice] + f11[voice]
            print('     voice site breakdown: pair=%d const=%d f2=%d total=%d'
                  % (f4[voice], f10[voice], f11[voice], nv))
            print('     other heavy push-calls: %s'
                  % {t: (f10[t], f11[t], f4[t]) for t, _ in allc.most_common(6) if t != voice and t != text})
        print('     pool preview: %s' % preview(ram, o, size, c10, 4))
    del ram
print('DONE', flush=True)
