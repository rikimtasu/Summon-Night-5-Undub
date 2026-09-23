"""Precisely locate the single USA text line that should carry vid 2287.

The correct gap is between the RETAINED anchor vids 2286 and 2288 (an earlier
window spanned vids 2279-2288 and was far too wide). Verifies the
"voice follows its line" convention on retained sites, and confirms the
candidate key is a real USA text call in the chapter-1 context.
"""
import os
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram, headers, classify, voice_sites, STATE
from disasm_align import disasm


def story_block(path, tag):
    ram = extract_ram(os.path.join(STATE, path) if not os.path.isabs(path) else path)
    for (o, size, c10) in headers(ram):
        tok = disasm(ram[o:o + c10 * 2], 12)
        if not tok or not (c10 - 4 <= tok[-1][0] + 1 <= c10):
            continue
        text, voice, c = classify(tok)
        if text is None or voice is None:
            continue
        return {'ram': ram, 'base': o, 'size': size, 'c10': c10, 'text': text,
                'voice': voice, 'tok': tok, 'sites': voice_sites(tok, voice), 'tag': tag}
    raise SystemExit('no story block in ' + path)


def text_calls(tok, textfunc):
    out = []
    for k, t in enumerate(tok):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == textfunc:
            s = None
            for b in (1, 2):
                if k - b < 0:
                    break
                p = tok[k - b]
                if p[1] == 50 and p[2] == 5 and p[4]:
                    s = p[4][0]
                    break
            out.append((t[0], s))
    return out


def pool_string(blk, c10, sidx):
    off = (c10 + sidx) * 2
    if off >= len(blk):
        return None
    e = blk.find(b'\x00', off)
    s = blk[off:e if e > 0 else off + 200]
    for enc in ('utf-8', 'shift_jis', 'latin-1'):
        try:
            return s.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


jp = story_block('NPJH50696_1.01_0.ppst', 'JP')
usa = story_block('ULUS10656_1.01_0.ppst', 'USA')
jp_blk = jp['ram'][jp['base']:jp['base'] + jp['size']]
usa_blk = usa['ram'][usa['base']:usa['base'] + usa['size']]
jp_sites = jp['sites']
usa_sites = usa['sites']
TARGET = 2287

lines = []
i = next(q for q, (u, k, v) in enumerate(jp_sites) if v == TARGET and k == 'const')
prev_j = next(jp_sites[q] for q in range(i - 1, -1, -1) if jp_sites[q][1] == 'const')
next_j = next(jp_sites[q] for q in range(i + 1, len(jp_sites)) if jp_sites[q][1] == 'const')


def usa_index(vid):
    for q, (u, k, v) in enumerate(usa_sites):
        if k == 'const' and v == vid:
            return q
    return None


ip, inx = usa_index(prev_j[2]), usa_index(next_j[2])
lo_u, hi_u = usa_sites[ip][0], usa_sites[inx][0]
usa_gap = [(u, s) for (u, s) in text_calls(usa['tok'], usa['text']) if lo_u < u < hi_u]
jp_gap = [(u, s) for (u, s) in text_calls(jp['tok'], jp['text']) if prev_j[0] < u < next_j[0]]

lines.append('JP gap between vid%d and vid%d (%d lines):' % (prev_j[2], next_j[2], len(jp_gap)))
for u, s in jp_gap:
    lines.append('  unit=%-6d %s' % (u, pool_string(jp_blk, jp['c10'], s)))
lines.append('')
lines.append('USA gap between vid%d (unit %d) and vid%d (unit %d) (%d lines):'
             % (prev_j[2], lo_u, next_j[2], hi_u, len(usa_gap)))
for u, s in usa_gap:
    key = (usa['c10'] + s) * 2
    lines.append('  unit=%-6d sidx=%-6s key=%-8d %s' % (u, s, key, pool_string(usa_blk, usa['c10'], s)))

# convention check on the retained anchors
lines.append('')
lines.append('Convention check (retained anchors):')
for vid in (prev_j[2], next_j[2]):
    qj = next(q for q, (u, k, v) in enumerate(jp_sites) if k == 'const' and v == vid)
    jp_b = [x for x in jp_gap if x[0] < jp_sites[qj][0]]
    qu = usa_index(vid)
    us_b = [x for x in usa_gap if x[0] < usa_sites[qu][0]]
    lines.append('  vid %d' % vid)
    if jp_b:
        lines.append('     JP  last line before voice: %s' % pool_string(jp_blk, jp['c10'], jp_b[-1][1]))
    if us_b:
        lines.append('     USA last line before voice: %s' % pool_string(usa_blk, usa['c10'], us_b[-1][1]))

jp_bt = [x for x in jp_gap if x[0] < jp_sites[i][0]]
lines.append('')
lines.append('TARGET vid%d -> JP line: %s' % (TARGET, pool_string(jp_blk, jp['c10'], jp_bt[-1][1])))
lines.append('USA c10 (chapter-1 context) = %d' % usa['c10'])
out = r'D:\Documents\Default Project\work\pin_target.txt'
open(out, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
print('\n'.join(lines))
print('wrote', out, flush=True)
