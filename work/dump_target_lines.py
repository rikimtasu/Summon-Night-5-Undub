"""Dump JP and USA text lines around a JP-only voice site to a UTF-8 file.

Writes work/target_dump.txt with the JP gap lines and the USA candidate lines
(including their table keys) so the bilingual match can be done by reading the
file (console mangles Shift-JIS).
"""
import os
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram, headers, classify, voice_sites, STATE
from find_missing_site_target import story_block, text_calls, pool_string

OUT = r'D:\Documents\Default Project\work\target_dump.txt'

jp = story_block('NPJH50696_1.01_0.ppst', 'JP')
usa = story_block('ULUS10656_1.01_0.ppst', 'USA')
jp_blk = jp['ram'][jp['base']:jp['base'] + jp['size']]
usa_blk = usa['ram'][usa['base']:usa['base'] + usa['size']]

TARGET_VID = int(sys.argv[1]) if len(sys.argv) > 1 else 2287
jp_sites = jp['sites']
usa_sites = usa['sites']
i = [q for q, (u, k, v) in enumerate(jp_sites) if v == TARGET_VID and k == 'const'][0]
prev = next(jp_sites[q] for q in range(i - 1, -1, -1) if jp_sites[q][1] == 'const')
nxt = next(jp_sites[q] for q in range(i + 1, len(jp_sites)) if jp_sites[q][1] == 'const')

# USA run anchored on next vid with prev vid nearby
j = None
for q, (u, k, v) in enumerate(usa_sites):
    if k == 'const' and v == nxt[2]:
        window = usa_sites[max(0, q - 8):q]
        if any(w[1] == 'const' and w[2] == prev[2] for w in window):
            j = q
            break

jp_texts = text_calls(jp['tok'], jp['text'])
jp_gap = [(u, s) for (u, s) in jp_texts if prev[0] < u < nxt[0]]
usa_lo = usa_sites[j - 8][0]
usa_hi = usa_sites[j][0]
usa_gap = [(u, s) for (u, s) in text_calls(usa['tok'], usa['text']) if usa_lo < u < usa_hi]

with open(OUT, 'w', encoding='utf-8') as f:
    f.write('TARGET vid=%d  JP unit=%d\n' % (TARGET_VID, jp_sites[i][0]))
    f.write('JP anchors: prev vid=%d unit=%d ; next vid=%d unit=%d\n' % (prev[2], prev[0], nxt[2], nxt[0]))
    f.write('USA anchors: prev unit=%d ; next unit=%d\n\n' % (usa_sites[j - 1][0], usa_sites[j][0]))
    f.write('=== JP gap text lines (%d) ===\n' % len(jp_gap))
    # the voice fires after the text whose call precedes it
    vp = [q for q, (u, s) in enumerate(jp_gap) if u < jp_sites[i][0]]
    last_before = jp_gap[vp[-1]] if vp else None
    for u, s in jp_gap:
        txt = pool_string(jp_blk, jp['c10'], s) or ''
        tag = '  <== JP line whose voice was deleted (voice fires just after)' if (u, s) == last_before else ''
        f.write('unit=%-6d sidx=%-6s %s%s\n' % (u, s, txt, tag))
    f.write('\n=== USA gap text lines (%d) ===\n' % len(usa_gap))
    for u, s in usa_gap:
        txt = pool_string(usa_blk, usa['c10'], s) or ''
        key = (usa['c10'] + s) * 2 if s is not None else '?'
        f.write('unit=%-6d sidx=%-6s key=%-8s %s\n' % (u, s, key, txt))
    f.write('\nUSA c10=%d\n' % usa['c10'])
print('wrote', OUT)
