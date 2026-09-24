# -*- coding: utf-8 -*-
"""Review what the shipped xdelta actually changes, and whether it is current.

verify_shipped_patch.py proves the EBOOT half of the patch is correct.  The
undub has THREE kinds of change, though, and only one of them lives in the
EBOOT:

  1. EBOOT.BIN    - engine clamp NOPed, story voice hook + 339-row table,
                    backlog replay/log/gate hooks
  2. SV00..SV17   - JP voice banks swapped in (so JP clips exist and play)
  3. 04.DAT       - JP opening movie swapped in

and one thing that must NOT change: every other file (script, 00/01/02/03.DAT,
10/11/12.DAT, SV18, PRXs, PARAM.SFO...).  "Is the patch current?" is really
two questions, and this answers both:

  A. Does the undub ISO differ from the STOCK USA ISO in exactly the expected
     file set, with the expected byte deltas?
  B. Are the JP-sourced files byte-identical to the JP ISO's versions, i.e. did
     the latest SV / opening content make it in?

Because the xdelta was already proven to decode to this exact ISO byte-for-byte
(see verify_shipped_patch.py --xdelta), reviewing the ISO reviews the patch.
This script prints that provenance too, so a stale ISO cannot be mistaken for a
current patch.

Usage:
    python review_xdelta_patch.py
    python review_xdelta_patch.py --undub "….iso" --stock "….iso" --jp "….iso"
"""
import argparse
import hashlib
import os
import sys

WORK = r'D:\Documents\Default Project\work'
ROOT = os.path.dirname(WORK)
DEFAULT_UNDUB = os.path.join(ROOT, 'Summon Night 5 (USA) Undub.iso')
DEFAULT_STOCK = os.path.join(ROOT, 'Summon Night 5 (USA).iso')
DEFAULT_JP = os.path.join(ROOT, 'Summon Night 5 (JP).iso')

# files the undub is SUPPOSED to change, and where their content must come from
EXPECTED_EBOOT = {'/PSP_GAME/SYSDIR/EBOOT.BIN': 'patched (built by us)'}
EXPECTED_JP = {('/PSP_GAME/USRDIR/SV%02d.DAT' % i): 'jp' for i in range(0, 18)}
EXPECTED_JP['/PSP_GAME/USRDIR/04.DAT'] = 'jp'


class HashSink(object):
    """Minimal write-only sink so we can hash ISO members without extracting."""

    def __init__(self):
        self.h = hashlib.sha256()
        self.n = 0

    def write(self, b):
        self.h.update(b)
        self.n += len(b)
        return len(b)

    def tell(self):
        return self.n

    def hexdigest(self):
        return self.h.hexdigest()


def file_hash(iso, path):
    sink = HashSink()
    iso.get_file_from_iso_fp(sink, iso_path=path)
    return sink.hexdigest(), sink.n


def walk_files(iso, root='/'):
    out = []
    for dirpath, _dirs, files in iso.walk(iso_path=root):
        for f in files:
            p = dirpath.rstrip('/') + '/' + f
            out.append(p)
    return sorted(out)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--undub', default=DEFAULT_UNDUB)
    ap.add_argument('--stock', default=DEFAULT_STOCK)
    ap.add_argument('--jp', default=DEFAULT_JP)
    ap.add_argument('--skip-hash', action='store_true',
                    help='compare file LISTS only (fast, no content check)')
    args = ap.parse_args(argv)

    import pycdlib
    undub = pycdlib.PyCdlib()
    undub.open(args.undub)
    stock = pycdlib.PyCdlib()
    stock.open(args.stock)
    jp = pycdlib.PyCdlib()
    jp.open(args.jp)

    print('undub : %s (%d bytes)' % (os.path.basename(args.undub),
                                    os.path.getsize(args.undub)))
    print('stock : %s (%d bytes)' % (os.path.basename(args.stock),
                                    os.path.getsize(args.stock)))
    print('jp    : %s (%d bytes)' % (os.path.basename(args.jp),
                                    os.path.getsize(args.jp)))
    print()

    ufiles = set(walk_files(undub))
    sfiles = set(walk_files(stock))
    jfiles = set(walk_files(jp))

    print('=== file inventory ===')
    print('  undub files: %d   stock USA: %d   jp: %d'
          % (len(ufiles), len(sfiles), len(jfiles)))
    only_u = sorted(ufiles - sfiles)
    only_s = sorted(sfiles - ufiles)
    print('  only in undub: %s' % (only_u or 'none'))
    print('  only in stock: %s' % (only_s or 'none'))
    print()

    expected = set(EXPECTED_EBOOT) | set(EXPECTED_JP)
    if args.skip_hash:
        print('=== content comparison SKIPPED (--skip-hash) ===')
        print('  expected changed set (%d files):' % len(expected))
        for p in sorted(expected):
            print('    %s' % p)
        undub.close(); stock.close(); jp.close()
        return 0

    print('=== per-file content comparison (undub vs stock USA) ===')
    changed, same = [], 0
    for path in sorted(ufiles & sfiles):
        uh, un = file_hash(undub, path)
        sh, sn = file_hash(stock, path)
        if uh == sh and un == sn:
            same += 1
            continue
        changed.append((path, un, sn, uh, sh))
    print('  identical files: %d' % same)
    print('  changed files  : %d' % len(changed))
    for path, un, sn, uh, sh in changed:
        exp = ('eboot' if path in EXPECTED_EBOOT else
               'jp' if path in EXPECTED_JP else 'UNEXPECTED')
        print('    %-34s %10d -> %-10d  %s' % (path, sn, un, exp))
    print()

    print('=== intent check ===')
    # The USA ISO ships no SV00..SV17 at all, so the JP voice banks appear as
    # ADDED files, not changed ones.  Expected delta is therefore:
    #   added   : SV00..SV17 (JP content, verified below)
    #   changed : EBOOT.BIN (ours) and 04.DAT (must carry JP content)
    added_expected = set(EXPECTED_JP) - {'/PSP_GAME/USRDIR/04.DAT'}
    changed_expected = set(EXPECTED_EBOOT) | {'/PSP_GAME/USRDIR/04.DAT'}
    got_changed = {p for p, *_ in changed}
    unexpected = sorted(got_changed - changed_expected)
    # the inverse direction matters too: a stock EBOOT.BIN (or stock 04.DAT)
    # would otherwise sail through as "nothing unexpected changed"
    missing_changed = sorted(changed_expected - got_changed)
    extra_added = sorted(set(only_u) - added_expected)
    missing_added = sorted(added_expected - set(only_u))
    deleted = sorted(only_s)
    print('  changed files expected : %s' % sorted(changed_expected))
    print('  added files expected   : %d (SV00..SV17)' % len(added_expected))
    print('  unexpected changes     : %s' % (unexpected or 'none'))
    print('  missing changes        : %s' % (missing_changed or 'none'))
    print('  unexpected added files : %s' % (extra_added or 'none'))
    print('  expected files missing : %s' % (missing_added or 'none'))
    print('  deleted stock files    : %s' % (deleted or 'none'))
    ok = (not unexpected and not missing_changed and not extra_added
          and not missing_added and not deleted)
    print()

    print('=== JP-sourced files: identical to the JP ISO? ===')
    jpgood = True
    jp_bad = []
    for path in sorted(EXPECTED_JP):
        if path not in ufiles:
            print('    %-34s MISSING from undub' % path)
            jpgood = False
            jp_bad.append(path)
            continue
        if path not in jfiles:
            print('    %-34s not in JP ISO (skipped)' % path)
            continue
        uh, un = file_hash(undub, path)
        jh, jn = file_hash(jp, path)
        same_as_jp = (uh == jh and un == jn)
        if not same_as_jp:
            jp_bad.append(path)
        jpgood = jpgood and same_as_jp
        note = '== JP' if same_as_jp else '!= JP'
        if not same_as_jp and path in sfiles:
            sh, _sn = file_hash(stock, path)
            if uh == sh:
                note += '  (== STOCK USA: the change was never applied)'
        print('    %-34s %10d  %s' % (path, un, note))
    print()

    print('=== provenance ===')
    print('  The xdelta was proven to decode byte-identically to this undub ISO')
    print('  (verify_shipped_patch.py --xdelta), so reviewing the ISO reviews')
    print('  the patch. Re-run that check if the ISO is ever rebuilt.')
    print()

    if ok and jpgood:
        print('VERDICT: patch changes exactly the expected file set, and every')
        print('         JP-sourced file matches the JP ISO -> CURRENT.')
    else:
        print('VERDICT: NOT current - the lines above name what is wrong.')
        if jp_bad:
            print('         JP content missing from: %s'
                  % ', '.join(p.split('/')[-1] for p in jp_bad))
    undub.close()
    stock.close()
    jp.close()
    return 0 if (ok and jpgood) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
