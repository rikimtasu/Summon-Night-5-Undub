# -*- coding: utf-8 -*-
"""Re-apply the JP opening movie (04.DAT) to the undub ISO, guarded.

WHY
---
The shipped patch carries the JP voice banks and the patched EBOOT, but its
04.DAT is byte-identical to the STOCK USA file, so the JP opening never made it
in.  build_v5 did swap it and did verify it; a later full rebuild regenerated
OUT_ISO from stock and the EBOOT-only patch step never restored it, because
that step only rewrites the EBOOT extent.  Nothing re-asserted 04.DAT, so the
loss was silent - the same class as the recorded v5r1 `add_fp` no-op.

This script does the swap the safe way and refuses to destroy anything:

  1. prove work/JP04.DAT really is the JP ISO's 04.DAT
  2. build a NEW iso (never in-place) with 04.DAT removed then re-added
  3. verify the new ISO: 04.DAT == JP, EBOOT byte-identical to the old one,
     every other file byte-identical
  4. only then move it into place, keeping the previous ISO as .pre_opening

Usage:
    python apply_jp_opening.py            # build + verify + install
    python apply_jp_opening.py --dry-run  # checks only
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths
from common import HashSink, member_hash, sha_file

WORK = paths.WORK
ROOT = paths.ROOT
UNDUB = os.path.join(ROOT, 'Summon Night 5 (USA) Undub.iso')
JPISO = os.path.join(ROOT, 'Summon Night 5 (JP).iso')
JP04 = os.path.join(WORK, 'JP04.DAT')
STAGED = os.path.join(ROOT, 'Summon Night 5 (USA) Undub.new.iso')
BACKUP = os.path.join(ROOT, 'Summon Night 5 (USA) Undub.pre_opening.iso')
OPENING = '/PSP_GAME/USRDIR/04.DAT'
EBOOT = '/PSP_GAME/SYSDIR/EBOOT.BIN'


# sha_file / HashSink / member_hash live in common.py (shared with
# review_xdelta_patch.py); Sink stays as an alias for back-compat.
Sink = HashSink


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)

    import pycdlib

    print('=== preflight ===')
    for p in (UNDUB, JPISO, JP04):
        if not os.path.isfile(p):
            raise SystemExit('missing: %s' % p)
    jp = pycdlib.PyCdlib()
    jp.open(JPISO)
    jh, jn = member_hash(jp, OPENING)
    jp.close()
    fh = sha_file(JP04)
    print('  JP ISO 04.DAT   : %d bytes  %s' % (jn, jh[:16]))
    print('  work/JP04.DAT   : %d bytes  %s' % (os.path.getsize(JP04),
                                                fh[:16]))
    if jh != fh:
        raise SystemExit('ABORT: work/JP04.DAT is not the JP ISO 04.DAT')
    print('  -> JP04.DAT confirmed as JP ISO content')

    old = pycdlib.PyCdlib()
    old.open(UNDUB)
    old_open_h, old_open_n = member_hash(old, OPENING)
    old_eboot_h, old_eboot_n = member_hash(old, EBOOT)
    files = []
    for dirpath, _d, fs in old.walk(iso_path='/'):
        for f in fs:
            files.append(dirpath.rstrip('/') + '/' + f)
    files = sorted(files)
    print('  undub 04.DAT    : %d bytes  %s' % (old_open_n, old_open_h[:16]))
    print('  undub EBOOT     : %d bytes  %s' % (old_eboot_n,
                                                 old_eboot_h[:16]))
    print('  undub files     : %d' % len(files))
    if args.dry_run:
        print('\nDRY RUN - no changes made.')
        old.close()
        return 0

    print('\n=== rebuild (staged, never in place) ===')
    if os.path.exists(STAGED):
        os.remove(STAGED)
    # rm_file BEFORE add_fp: pycdlib silently ignores adding over an existing
    # member (the recorded v5r1 bug).
    old.rm_file(iso_path=OPENING)
    # The handle MUST stay open until AFTER write(): add_fp only records it and
    # the bytes are read during write(). build_v5.py keeps its handles alive in
    # an `fps` list for exactly this reason - closing early fails with
    # "ValueError: seek of closed file".
    fp = open(JP04, 'rb')
    old.add_fp(fp, os.path.getsize(JP04), iso_path=OPENING)
    print('  04.DAT removed and re-added from JP (%d bytes)' % jn)
    print('  writing %s (1.3 GB, please wait)...' % os.path.basename(STAGED))
    old.write(STAGED)
    old.close()
    fp.close()
    print('  written: %d bytes' % os.path.getsize(STAGED))

    print('\n=== verify the staged ISO before installing ===')
    new = pycdlib.PyCdlib()
    new.open(STAGED)
    nh, nn = member_hash(new, OPENING)
    ne, nen = member_hash(new, EBOOT)
    print('  04.DAT == JP        : %s' % (nh == jh))
    print('  EBOOT unchanged     : %s' % (ne == old_eboot_h))
    bad = []
    # compare every other member against the ORIGINAL iso
    orig = pycdlib.PyCdlib()
    orig.open(UNDUB)
    for p in files:
        if p == OPENING:
            continue
        a, _ = member_hash(new, p)
        b, _ = member_hash(orig, p)
        if a != b:
            bad.append(p)
    print('  other files intact  : %s' % (not bad))
    if bad:
        print('    CHANGED: %s' % bad)
    new.close()
    orig.close()

    if nh != jh or ne != old_eboot_h or bad:
        print('\nABORT: staged ISO failed verification; %s left untouched.'
              % os.path.basename(UNDUB))
        return 1

    print('\n=== install ===')
    if os.path.exists(BACKUP):
        os.remove(BACKUP)
    shutil.move(UNDUB, BACKUP)
    shutil.move(STAGED, UNDUB)
    print('  previous ISO kept as: %s' % os.path.basename(BACKUP))
    print('  new ISO installed  : %s' % os.path.basename(UNDUB))
    print('  new ISO sha256     : %s' % sha_file(UNDUB))
    print('\nNext: re-encode the xdelta, then re-run review_xdelta_patch.py')
    print('      and verify_shipped_patch.py.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
