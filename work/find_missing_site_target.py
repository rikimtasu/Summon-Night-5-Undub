"""Locate the USA text line that should carry a JP-only voice id.

Anchors on the voice sites immediately before/after the deleted one (those
vids are retained in USA, so they bracket the corresponding region), then
lists the USA text calls in that gap with their string index, decoded text,
and the table key (2*(c10+stridx)) an entry would use. Prints the JP text
around the deleted site for a bilingual sanity check.
"""
import collections
import os
import struct
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
    """[(unit, stridx)] text calls, arg = immediately preceding op50 f1=5"""
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


jp = story_block(sys.argv[1] if len(sys.argv) > 1 else 'NPJH50696_1.01_0.ppst', 'JP')
usa = story_block(sys.argv[2] if len(sys.argv) > 2 else 'ULUS10656_1.01_0.ppst', 'USA')

TARGET_VID = int(sys.argv[3]) if len(sys.argv) > 3 else 2287

jp_sites = jp['sites']
usa_sites = usa['sites']
jp_blk = jp['ram'][jp['base']:jp['base'] + jp['size']]
usa_blk = usa['ram'][usa['base']:usa['base'] + usa['size']]

idx = [i for i, (u, k, v) in enumerate(jp_sites) if v == TARGET_VID and k == 'const']
print('JP-only const site %d occurrences: %s' % (TARGET_VID, idx))
i = idx[0]
print('JP voice sites around it:')
for j in range(max(0, i - 4), min(len(jp_sites), i + 5)):
    mark = '  <== DELETED IN USA' if j == i else ''
    print('   [%d] unit=%-6d %-5s vid=%d%s' % (j, jp_sites[j][0], jp_sites[j][1], jp_sites[j][2], mark))

# JP text around the site
jp_texts = text_calls(jp['tok'], jp['text'])
near = [(u, s) for (u, s) in jp_texts if jp_sites[i][0] - 400 <= u <= jp_sites[i][0] + 400]
print('\nJP text lines near the site:')
for u, s in near:
    txt = pool_string(jp_blk, jp['c10'], s) if s is not None else None
    print('   unit=%-6d sidx=%-6s %s' % (u, s, (txt or '')[:70]))

# anchors: nearest retained site before and after
prev = None
nxt = None
for j in range(i - 1, -1, -1):
    if jp_sites[j][1] == 'const':
        prev = jp_sites[j]
        break
for j in range(i + 1, len(jp_sites)):
    if jp_sites[j][1] == 'const':
        nxt = jp_sites[j]
        break
print('\nanchors: prev=%s next=%s' % (prev, nxt))

# find the matching run in USA: unique occurrence of the nxt vid preceded
# (within 6 sites) by the prev vid
def find_run(usa_sites, prev_vid, nxt_vid, span=8):
    hits = []
    for j, (u, k, v) in enumerate(usa_sites):
        if k != 'const' or v != nxt_vid:
            continue
        window = usa_sites[max(0, j - span):j]
        if any(w[1] == 'const' and w[2] == prev_vid for w in window):
            hits.append(j)
    return hits


runs = find_run(usa_sites, prev[2], nxt[2])
print('USA anchor runs found: %s' % runs)
for j in runs:
    print('\nUSA sites [%d..%d]:' % (j - 8, j + 2))
    for q in range(max(0, j - 8), min(len(usa_sites), j + 3)):
        u, k, v = usa_sites[q]
        print('   unit=%-6d %-5s vid=%d%s' % (u, k, v, '   <-- gap start' if q == j - 1 else ''))
    lo = usa_sites[max(0, j - 8)][0]
    hi = usa_sites[j][0]
    gap = [(u, s) for (u, s) in text_calls(usa['tok'], usa['text']) if lo < u < hi]
    print('   USA text calls inside the gap: %d' % len(gap))
    for u, s in gap:
        txt = pool_string(usa_blk, usa['c10'], s) if s is not None else None
        key = (usa['c10'] + s) * 2 if s is not None else None
        print('     unit=%-6d sidx=%-6s key=%-8s %s' % (u, s, key, (txt or '')[:70]))
print('DONE', flush=True)
