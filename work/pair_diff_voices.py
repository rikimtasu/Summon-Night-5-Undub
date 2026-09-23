"""Diff the voice-site multisets of a JP/USA block pair (same scene).

Reports, per arg form, which vids each side has, so a "deleted" site (JP only)
or a localizer "added" site (USA only) is identified exactly.
"""
import collections
import os
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
from pair_report import extract_ram, headers, classify, voice_sites, STATE
from disasm_align import disasm

# story blocks: the ones with a text function (system blocks have none)
def story_block(path, tag):
    ram = extract_ram(os.path.join(STATE, path) if not os.path.isabs(path) else path)
    for (o, size, c10) in headers(ram):
        tok = disasm(ram[o:o + c10 * 2], 12)
        if not tok or not (c10 - 4 <= tok[-1][0] + 1 <= c10):
            continue
        text, voice, c = classify(tok)
        if text is None or voice is None:
            continue
        return {'ram': ram, 'base': o, 'size': size, 'c10': c10,
                'text': text, 'voice': voice, 'tok': tok,
                'sites': voice_sites(tok, voice), 'tag': tag}
    raise SystemExit('no story block in ' + path)


jp = story_block(sys.argv[1] if len(sys.argv) > 1 else 'NPJH50696_1.01_0.ppst', 'JP')
usa = story_block(sys.argv[2] if len(sys.argv) > 2 else 'ULUS10656_1.01_0.ppst', 'USA')

print('JP  c10=%-6d textfunc=%d voicefunc=%d sites=%d' % (jp['c10'], jp['text'], jp['voice'], len(jp['sites'])))
print('USA c10=%-6d textfunc=%d voicefunc=%d sites=%d' % (usa['c10'], usa['text'], usa['voice'], len(usa['sites'])))

for kind in ('const', 'f2', 'pair'):
    a = collections.Counter(v for _, k, v in jp['sites'] if k == kind)
    b = collections.Counter(v for _, k, v in usa['sites'] if k == kind)
    if not a and not b:
        continue
    only_jp = a - b
    only_usa = b - a
    print('\n%s: JP %d / USA %d' % (kind, sum(a.values()), sum(b.values())))
    if only_jp:
        print('   JP-only (deleted in USA): %s' % dict(sorted(only_jp.items())))
    if only_usa:
        print('   USA-only (localizer-added): %s' % dict(sorted(only_usa.items())))
    if not only_jp and not only_usa:
        print('   identical multisets')

# where does a JP-only site sit relative to its neighbours?
for kind in ('const', 'f2'):
    a = collections.Counter(v for _, k, v in jp['sites'] if k == kind)
    b = collections.Counter(v for _, k, v in usa['sites'] if k == kind)
    only_jp = a - b
    if not only_jp:
        continue
    units = [u for (u, k, v) in jp['sites'] if k == kind and only_jp.get(v)]
    print('\nJP-only %s site units: %s' % (kind, units))
    for u in units:
        idx = [i for i, t in enumerate(jp['tok']) if t[0] == u][0]
        print('   token context around unit %d:' % u)
        for t in jp['tok'][max(0, idx - 6):idx + 3]:
            print('      %s' % (t,))
print('DONE', flush=True)
