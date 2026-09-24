# -*- coding: utf-8 -*-
"""Probe the game data containers for story-script content, offline.

Question: can the per-chapter story blocks be recovered from the ISOs (or
already-extracted USRDIR files) WITHOUT booting the game per chapter?

The census tool currently needs a RAM dump because the blocks were only ever
observed in RAM.  But the game must read the script from somewhere.  Two
outcomes decide the next step:

  A. the block header magic (0x10000201/0x10000002) or known dialogue text
     appears verbatim in a container -> the script is stored expanded and we
     can enumerate every chapter straight from the file, no playtesting.

  B. neither appears -> the container is compressed/encoded, and the next step
     is to identify the EBOOT routine that expands it (the header is built at
     runtime), so the same decompression can be re-run offline on all chapters
     at once instead of one capture per chapter.

Run:  python probe_script_containers.py
"""
import csv
import os
import struct
import sys

WORK = r'D:\Documents\Default Project\work'

CONTAINERS = [
    ('jp', os.path.join(WORK, 'JP', 'PSP_GAME', 'USRDIR', '00.DAT')),
    ('jp', os.path.join(WORK, 'JP', 'PSP_GAME', 'USRDIR', '02.DAT')),
    ('jp', os.path.join(WORK, 'JP', 'PSP_GAME', 'USRDIR', '10.DAT')),
    ('usa', os.path.join(WORK, 'USA', 'PSP_GAME', 'USRDIR', '00.DAT')),
    ('usa', os.path.join(WORK, 'USA', 'PSP_GAME', 'USRDIR', '02.DAT')),
    ('usa', os.path.join(WORK, 'USA', 'PSP_GAME', 'USRDIR', '10.DAT')),
]

MAGIC_PAIR = struct.pack('<II', 0x10000201, 0x10000002)
MAGIC1 = struct.pack('<I', 0x10000201)


def entropy(sample):
    import collections
    import math
    c = collections.Counter(sample)
    n = len(sample)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def known_strings():
    """A few real JP + USA dialogue lines, from the census bilingual TSV."""
    tsv = os.path.join(WORK, 'voice_bilingual.tsv')
    out = []
    if not os.path.exists(tsv):
        return out
    with open(tsv, encoding='utf-8') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            for field in ('usa_text', 'jp_prev_text'):
                txt = (row.get(field) or '').strip()
                if len(txt) >= 18 and not row.get(field).startswith('?'):
                    out.append((field, txt[:40]))
            if len(out) >= 6:
                break
    return out


def find_all(hay, needle, limit=8):
    hits, start = [], 0
    while True:
        o = hay.find(needle, start)
        if o < 0 or len(hits) >= limit:
            break
        hits.append(o)
        start = o + 1
    return hits


def main():
    print('known probe strings (from voice_bilingual.tsv):')
    probes = known_strings()
    for field, txt in probes:
        print('  %-12s %r' % (field, txt))
    if not probes:
        print('  (TSV missing - falling back to structural probes only)')

    print()
    verdict = {}
    for tag, path in CONTAINERS:
        name = '%s/%s' % (tag, os.path.basename(path))
        if not os.path.isfile(path):
            print('%-14s MISSING' % name)
            continue
        data = open(path, 'rb').read()
        ent = entropy(data[:1 << 20])
        pairs = find_all(data, MAGIC_PAIR)
        ones = find_all(data, MAGIC1, 20)
        print('%-14s %10d bytes  entropy(1MiB)=%.3f  magic_pair=%d '
              'magic_dword=%d' % (name, len(data), ent, len(pairs), len(ones)))
        if pairs:
            print('               magic pair at %s' %
                  ', '.join('0x%X' % p for p in pairs))
        for field, txt in probes:
            for enc in ('utf-8', 'shift_jis'):
                raw = txt.encode(enc, 'ignore')
                if len(raw) < 12:
                    continue
                hits = find_all(data, raw, 3)
                if hits:
                    print('               TEXT HIT [%s/%s] %r at %s'
                          % (field, enc, txt,
                             ', '.join('0x%X' % h for h in hits)))
        verdict[name] = bool(pairs)

    print()
    hit = [k for k, v in verdict.items() if v]
    if hit:
        print('VERDICT A: block header found verbatim in %s' % ', '.join(hit))
        print('         -> script is stored expanded; every chapter can be')
        print('            enumerated straight from the container.')
    else:
        print('VERDICT B: no block header in any container.')
        print('         -> script is compressed/encoded on disk. Next step:')
        print('            identify the EBOOT routine that builds the header')
        print('            (hdr_magic_scan.py materializations) and re-run its')
        print('            expansion offline, which yields ALL chapters in one')
        print('            pass instead of one RAM capture per chapter.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
