"""Pair report for two PPSSPP save states (JP + USA) of the same scene.

For each state: locate resident script blocks by header magic, decode each
block's token stream, classify its text/voice function ids with the
calibration-free push-count rule, and census voice sites by arg form.
Also reports the text-call key (byte offset of the line's string in the
block) that a future table entry would use.
"""
import collections
import os
import struct
import sys

import zstandard

sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

M1 = struct.pack('<I', 0x10000201)
M2 = struct.pack('<I', 0x10000002)
STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory', 'no Memory section'
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
    """returns (textfunc, voicefunc, counters) where counters[f][target]"""
    c = {5: collections.Counter(), 4: collections.Counter(),
         10: collections.Counter(), 11: collections.Counter()}
    for k in range(1, len(tok)):
        t = tok[k]
        if not (t[1] == 52 and t[2] == 1 and t[4]):
            continue
        p = tok[k - 1]
        if p[1] == 50 and p[2] in c:
            c[p[2]][t[4][0]] += 1
    text = c[5].most_common(1)[0][0] if c[5] else None
    voice = c[4].most_common(1)[0][0] if c[4] else None
    return text, voice, c


def text_lines(tok, textfunc):
    """[(unit, key_bytes, string)] for every text call of this block"""
    out = []
    for k, t in enumerate(tok):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == textfunc:
            sidx = None
            for b in range(1, 4):
                if k - b < 0:
                    break
                p = tok[k - b]
                if p[1] == 50 and p[2] == 5 and p[4]:
                    sidx = p[4][0]
                    break
            out.append((t[0], sidx))
    return out


def voice_sites(tok, voicefunc):
    """[(unit, kind, vid)] for every voice call of this block"""
    out = []
    for k, t in enumerate(tok):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == voicefunc:
            if k < 1:
                continue
            p = tok[k - 1]
            if p[1] != 50:
                continue
            if p[2] == 10 and p[4]:
                out.append((t[0], 'const', p[4][0]))
            elif p[2] == 11:
                out.append((t[0], 'f2', p[3] - 1))
            elif p[2] == 4 and p[4]:
                out.append((t[0], 'pair', p[4][0]))
    return out


def report(path, tag):
    ram = extract_ram(path if os.path.isabs(path) else os.path.join(STATE, path))
    print('=== %s (%s) ===' % (os.path.basename(path), tag))
    res = []
    for (o, size, c10) in headers(ram):
        tok = disasm(ram[o:o + c10 * 2], 12)
        if not tok or not (c10 - 4 <= tok[-1][0] + 1 <= c10):
            print('  base=0x%X size=%d c10=%d  LANDING FAIL' % (o, size, c10))
            continue
        text, voice, c = classify(tok)
        nlines = c[5][text] if text is not None else 0
        vs = voice_sites(tok, voice) if voice is not None else []
        kinds = collections.Counter(k for _, k, _ in vs)
        consts = sorted(v for _, k, v in vs if k == 'const')
        pairs = sorted(v for _, k, v in vs if k == 'pair')
        print('  base=0x%X size=%-7d c10=%-6d textfunc=%-5s lines=%-5d voicefunc=%-5s '
              'sites=%-5d %s'
              % (o, size, c10, text, nlines, voice, len(vs), dict(kinds)))
        if consts:
            print('      const vids: %d, range %d..%d' % (len(consts), consts[0], consts[-1]))
        if pairs:
            print('      pair  vids: %d, range %d..%d' % (len(pairs), pairs[0], pairs[-1]))
        res.append({'base': o, 'size': size, 'c10': c10, 'text': text, 'voice': voice,
                    'tok': tok, 'voice_sites': vs, 'text_lines': text_lines(tok, text) if text else []})
    del ram
    return res


if __name__ == '__main__':
    args = sys.argv[1:]
    jp = report(args[0] if args else 'NPJH50696_1.01_0.ppst', 'JP')
    print()
    usa = report(args[1] if len(args) > 1 else 'ULUS10656_1.01_0.ppst', 'USA')
    print()
    print('=== pair summary ===')
    for tag, blocks in (('JP', jp), ('USA', usa)):
        for b in blocks:
            print('  %-3s c10=%-6d lines=%-5d voice_sites=%d'
                  % (tag, b['c10'], len(b['text_lines']), len(b['voice_sites'])))
print('DONE', flush=True)
