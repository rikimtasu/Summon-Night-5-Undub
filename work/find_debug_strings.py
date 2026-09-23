# -*- coding: utf-8 -*-
"""Compare JP EBOOT string decodings and sweep both builds for debug/chapter UI."""
JP = open(r'D:\Documents\Default Project\EBOOT_JP_decrypted.bin', 'rb').read()
USA = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()


def strings(data, lo, hi, enc, require_kana=False):
    seg = data[lo:hi]
    out = []
    i = 0
    while i < len(seg):
        e = seg.find(b'\x00', i)
        if e < 0:
            break
        s = seg[i:e]
        if len(s) >= 2:
            try:
                t = s.decode(enc)
            except Exception:
                t = None
            if t and (not require_kana or any(ord(c) > 0x3000 for c in t)):
                if all(ord(c) >= 0x20 or c in '\t' for c in t):
                    out.append((lo + i, t))
        i = e + 1
    return out


# --- determine JP encoding by sampling ---
lo, hi = 0x1F3000, 0x200000
seg = JP[lo:hi]
samples = []
i = 0
while len(samples) < 6 and i < len(seg):
    e = seg.find(b'\x00', i)
    if e < 0:
        break
    s = seg[i:e]
    if len(s) >= 3 and any(b > 0x7F for b in s):
        samples.append(s)
    i = e + 1
print('=== JP encoding probe ===')
for s in samples:
    for enc in ('shift_jis', 'utf-8'):
        try:
            print('  %-10s %s' % (enc, s.decode(enc)[:40]))
        except Exception as e:
            print('  %-10s <decode error>' % enc)
    print('  raw:', s[:24].hex())
    print()

KW = {
    'chapter': '\u7ae0', 'scene': '\u30b7\u30fc\u30f3', 'debug': '\u30c7\u30d0\u30c3\u30b0',
    'test': '\u30c6\u30b9\u30c8', 'verify': '\u691c\u8a3c', 'develop': '\u958b\u767a',
    'bug': '\u4e0d\u5177\u5408', 'screen': '\u753b\u9762', 'jump': '\u30b8\u30e3\u30f3\u30d7',
    'unlock': '\u958b\u653e', 'select': '\u9078\u629e', 'data': '\u30c7\u30fc\u30bf',
    'warp': '\u30ef\u30fc\u30d7', 'start': '\u958b\u59cb', 'end': '\u7d42\u4e86',
    'clear': '\u30af\u30ea\u30a2', 'part': '\u7bc0',
}
KWU = {'debug': 'debug', 'test': 'test', 'chapter': 'chapter', 'scene': 'scene',
       'jump': 'jump', 'unlock': 'unlock', 'select': 'select', 'warp': 'warp',
       'cheat': 'cheat', 'stage': 'stage', 'skip': 'skip', 'part': 'part',
       'mission': 'mission', 'flag': 'flag'}

for tag, data, rng, encs, kws in (
        ('JP', JP, (0x1F3000, 0x210000), ('shift_jis', 'utf-8'), KW),
        ('USA', USA, (0x210000, 0x230000), ('utf-8',), KWU)):
    for enc in encs:
        ss = strings(data, rng[0], rng[1], enc)
        hits = [(o, t, [k for k, v in kws.items() if v in t]) for o, t in ss]
        hits = [h for h in hits if h[2]]
        print('=== %s as %s: %d strings, %d keyword hits ===' % (tag, enc, len(ss), len(hits)))
        for o, t, tg in hits[:45]:
            try:
                disp = t[:44]
            except Exception:
                disp = repr(t[:44])
            print('  0x%06X [%-16s] %s' % (o, ','.join(tg), disp))
print('DONE', flush=True)
