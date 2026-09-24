# -*- coding: utf-8 -*-
"""Extract the USRDIR containers we never examined, and search them for the
story-script block.

Only 00.DAT / 02.DAT / 10.DAT were ever pulled from the ISOs, and none of them
contains the block header (0x10000201) or any known dialogue.  The USRDIR also
holds 01.DAT, 03.DAT, 11.DAT and 12.DAT, which were never extracted.  This pulls
the plausible ones straight from the ISOs and applies the same two tests:

  * block header magic present  -> script stored expanded: every chapter can
    be enumerated from the file, no game boot at all.
  * known dialogue present (utf-8 / shift_jis / utf-16le) -> same conclusion
    even if the header is built by code.
  * neither -> the container is packed; note its size/entropy for the expander
    RE (the 0x10000201 constant exists exactly once per EBOOT but has no code
    xref, so the header most likely travels with the packed stream).

12.DAT is skipped: the notes record it as the PSMF movie.

Run:  python probe_remaining_containers.py
"""
import hashlib
import os
import struct
import sys

WORK = r'D:\Documents\Default Project\work'
ISOS = {
    'jp': os.path.join(os.path.dirname(WORK), 'Summon Night 5 (JP).iso'),
    'usa': os.path.join(os.path.dirname(WORK), 'Summon Night 5 (USA).iso'),
}
WANT = ('01.DAT', '03.DAT', '11.DAT')
MAGIC1 = struct.pack('<I', 0x10000201)
MAGIC_PAIR = struct.pack('<II', 0x10000201, 0x10000002)
PROBES = [b'It was a great war', b'Long, long ago', b'world of Lyndbaum']


def dest(tag, name):
    d = os.path.join(WORK, tag.upper(), 'PSP_GAME', 'USRDIR')
    os.makedirs(d, exist_ok=True)
    return d, os.path.join(d, name)


def extract(tag, name):
    out = dest(tag, name)
    if os.path.isfile(out[1]) and os.path.getsize(out[1]) > 0:
        return out[1], 'cached'
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.open(ISOS[tag])
    try:
        with open(out[1], 'wb') as fh:
            iso.get_file_from_iso_fp(fh, iso_path='/PSP_GAME/USRDIR/' + name)
    finally:
        iso.close()
    return out[1], 'extracted'


def entropy(sample):
    import collections
    import math
    c = collections.Counter(sample)
    n = len(sample)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def probe(path):
    data = open(path, 'rb').read()
    res = {
        'size': len(data),
        'ent': entropy(data[:1 << 20]),
        'magic1': data.count(MAGIC1),
        'pair': data.count(MAGIC_PAIR),
        'texts': [],
        'head': data[:48].hex(),
    }
    for p in PROBES:
        for enc in ('utf-8', 'shift_jis', 'utf-16-le'):
            raw = p.decode('ascii').encode(enc, 'ignore')
            if len(raw) < 12:
                continue
            o = data.find(raw)
            if o >= 0:
                res['texts'].append((p.decode('ascii'), enc, o))
    return res


def main():
    hits = []
    for tag in ('jp', 'usa'):
        for name in WANT:
            try:
                path, how = extract(tag, name)
            except Exception as exc:                  # noqa: BLE001
                print('%-4s %-9s EXTRACT FAIL: %s' % (tag, name, exc))
                continue
            r = probe(path)
            print('%-4s %-9s %-10s %11d bytes  ent=%.3f  magic=%d pair=%d  '
                  'head=%s' % (tag, name, how, r['size'], r['ent'],
                               r['magic1'], r['pair'], r['head'][:32]))
            for t in r['texts']:
                print('        TEXT HIT %-18s %-10s at 0x%X' % t)
                hits.append((tag, name, t))
            if r['magic1'] or r['texts']:
                hits.append((tag, name, 'magic' if r['magic1'] else 'text'))

    print()
    if hits:
        print('VERDICT: story script found in a container (see hits above).')
        print('Every chapter can then be enumerated from the file itself -')
        print('no per-chapter RAM capture, no playtesting.')
    else:
        print('VERDICT: not in the newly extracted containers either.')
        print('Remaining candidates: 12.DAT (PSMF movie, unlikely), or the')
        print('script is packed inside 02.DAT. Next step would be identifying')
        print('the EBOOT expander - note the 0x10000201 constant exists once')
        print('per EBOOT with no code xref, so the header most likely travels')
        print('inside the packed stream itself.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
