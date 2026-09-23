# -*- coding: utf-8 -*-
"""Dump JP EBOOT UTF-8 strings around demo/debug-like hits to a UTF-8 file."""
JP = open(r'D:\Documents\Default Project\EBOOT_JP_decrypted.bin', 'rb').read()
lo, hi = 0x1F3000, 0x210000
seg = JP[lo:hi]
items = []
i = 0
while i < len(seg):
    e = seg.find(b'\x00', i)
    if e < 0:
        break
    s = seg[i:e]
    if len(s) >= 2:
        try:
            t = s.decode('utf-8')
        except Exception:
            t = None
        if t and all(ord(c) >= 0x20 for c in t):
            items.append((lo + i, t))
    i = e + 1

KW = {
    'demo': '\u30c7\u30e2',          # デモ
    'debug': '\u30c7\u30d0\u30c3\u30b0',
    'test': '\u30c6\u30b9\u30c8',
    'chapter': '\u7ae0',
    'scene': '\u30b7\u30fc\u30f3',
    'unlock': '\u958b\u653e',
    'jump': '\u30b8\u30e3\u30f3\u30d7',
    'warp': '\u30ef\u30fc\u30d7',
    'part': '\u7bc0',               # 節
    'volume': '\u5377',             # 巻
    'operate': '\u64cd\u4f5c',     # 操作
    'monitor': '\u76e3\u8996',     # 監視
    'confirm': '\u78ba\u8a8d',     # 確認
}
out = []
out.append('total JP UTF-8 strings: %d' % len(items))
for name, kw in KW.items():
    hits = [(o, t) for o, t in items if kw in t]
    out.append('\n== %s (%s): %d ==' % (name, kw, len(hits)))
    for o, t in hits[:25]:
        out.append('  0x%06X %s' % (o, t[:60]))

# context dump around any demo hit
demo_hits = [(o, t) for o, t in items if '\u30c7\u30e2' in t]
for o, t in demo_hits:
    idx = next(k for k, (oo, _) in enumerate(items) if oo == o)
    out.append('\n--- context around 0x%06X (%s) ---' % (o, t[:40]))
    for oo, tt in items[max(0, idx - 12):idx + 13]:
        out.append('  0x%06X %s' % (oo, tt[:60]))

path = r'D:\Documents\Default Project\work\jp_debug_strings.txt'
open(path, 'w', encoding='utf-8').write('\n'.join(out) + '\n')
print('wrote', path, '(%d lines)' % len(out))
