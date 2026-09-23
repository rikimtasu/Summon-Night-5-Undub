# -*- coding: utf-8 -*-
"""Probe the SN5 save format: header, structure, and variable fields.

Compares two USA saves and two JP saves byte-wise to locate progress-dependent
fields (chapter id, flags, unlocks). If the data is encrypted we report entropy
and any header magic; if plaintext we hunt for small integer fields that differ.
"""
import collections
import os

SD = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
FILES = {
    'USA46': os.path.join(SD, 'ULUS10656SN5GAME46', 'DATA.BIN'),
    'USA47': os.path.join(SD, 'ULUS10656SN5GAME47', 'DATA.BIN'),
    'JP00': os.path.join(SD, 'NPJH50696SN5GAME00', 'DATA.BIN'),
    'JP01': os.path.join(SD, 'NPJH50696SN5GAME01', 'DATA.BIN'),
    'JP05': os.path.join(SD, 'NPJH50696SN5GAME05', 'DATA.BIN'),
    'SYS_JP': os.path.join(SD, 'NPJH50696SN5SYSTEM', 'DATA.BIN'),
    'SYS_USA': os.path.join(SD, 'ULUS10656SN5SYSTEM', 'DATA.BIN'),
}


def entropy(b):
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * (v / n and (v / n).__class__ and 0) for v in []) or \
        sum(-(v / n) * (len(bin(v)) and __import__('math').log2(v / n)) for v in c.values())


data = {}
for k, p in FILES.items():
    if os.path.isfile(p):
        data[k] = open(p, 'rb').read()
    else:
        print('missing', k, p)

for k, b in data.items():
    print('%-8s size=%-8d head=%s' % (k, len(b), b[:32].hex()))
    ent = 0.0
    c = collections.Counter(b)
    n = len(b)
    import math
    ent = -sum((v / n) * math.log2(v / n) for v in c.values())
    print('         entropy=%.3f bits/byte  zero%%=%.1f' % (ent, 100.0 * c[0] / n))

# compare same-version pairs
def diffmap(a, b, label):
    if a is None or b is None:
        return
    d = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
    print('\n%s: %d/%d bytes differ (%.1f%%)' % (label, len(d), len(a), 100.0 * len(d) / len(a)))
    if not d:
        return
    # group into runs
    runs = []
    s = d[0]
    p = d[0]
    for i in d[1:]:
        if i - p <= 16:
            p = i
        else:
            runs.append((s, p))
            s = i
            p = i
    runs.append((s, p))
    print('  %d differing region(s); first 25:' % len(runs))
    for (s, e) in runs[:25]:
        n = e - s + 1
        print('    0x%06X-0x%06X (%4d B)  A=%s  B=%s'
              % (s, e, n, a[s:min(e + 1, s + 16)].hex(), b[s:min(e + 1, s + 16)].hex()))


if 'USA46' in data and 'USA47' in data:
    diffmap(data['USA46'], data['USA47'], 'USA GAME46 vs GAME47')
if 'JP00' in data and 'JP01' in data:
    diffmap(data['JP00'], data['JP01'], 'JP GAME00 vs GAME01')
if 'USA46' in data and 'JP00' in data:
    diffmap(data['USA46'], data['JP00'], 'USA46 vs JP00 (cross-version)')
print('DONE', flush=True)
