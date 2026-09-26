# -*- coding: utf-8 -*-
"""Re-derive a loader-fixup address set for the decrypted USA EBOOT.

WHAT THE TRACKED FILE IS
------------------------
`work/usa_loader_diff.pkl` (pickled `set` of file vaddrs, FVA = file
offset - 0xC0) is the AUTHORITATIVE "words the PSP loader rewrites after
mapping the file" set:

  * build_v4.py asserts every word it writes is absent from it;
  * verify_shipped_patch.py re-checks the shipped EBOOT against it.

Writing into a word the loader also writes is exactly what bricked v3, so this
guard is load-bearing (verify_shipped_patch.py check 7).

This module is a RECOVERY/REPRODUCIBILITY tool, not the generator of record.
The tracked set (75,683 entries) is restorable from git history:

    git log --oneline -- work/usa_loader_diff.pkl
    git checkout <rev>^ -- work/usa_loader_diff.pkl

METHOD, AND WHY A RE-DERIVED SET IS ONLY A SUPERSET
---------------------------------------------------
Word-compare a PPSSPP save state of a **stock** (unpatched) USA build against
the decrypted EBOOT: the RAM image starts at 0x08000000 and the module is
linked at 0x08804000, so module RAM offset = 0x08804000 - 0x08000000 + fva.

Measured here: re-derivation finds 234,102 words vs the tracked 75,683, i.e. a
superset apart from a few addresses (e.g. 0x230114..0x2302xx) that the tracked
state happened to leave untouched because runtime code had already written
there.  Both sets reject zero of the shipped patch's 1,168 written words, so
both are safe; the tracked set is simply tighter.  Over-approximating can only
reject a candidate patch site, never let a colliding one through.

A state captured on a PATCHED build must never be used (the patch's own writes
would be recorded as "fixups"); the script refuses any state whose clamp/hook
words are not the stock ones.

Usage
-----
    python loader_fixups.py                        # compare, WRITES NOTHING
    python loader_fixups.py --write --out super.pkl   # dump the superset
    python loader_fixups.py --state PATH           # pick the state
"""
import argparse
import os
import pickle
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

SEG = 0xC0
RT = 0x08804000
RAM_BASE = 0x08000000
MOD_OFF = RT - RAM_BASE                      # 0x804000

# stock words that identify an UNPATCHED module in RAM
STOCK_WORDS = {0x17904: 0x0205282B,          # sltu  a1, s0, a1   (clamp)
               0x17908: 0x54A00001,          # bnel  a1, zero, ... (clamp)
               0x1790C: 0x2410FFFF,          # addiu s0, zero, -1  (clamp delay)
               0x17848: 0xAFA20008}          # sw    v0, 8(sp)     (hook site)

TRACKED = os.path.join(paths.WORK, 'usa_loader_diff.pkl')


def default_states():
    """Candidate states: the USA PPSSPP_STATE dir, name order."""
    d = paths.state_dir()
    if not d or not os.path.isdir(d):
        return []
    return sorted(os.path.join(d, n) for n in os.listdir(d)
                  if n.startswith('ULUS10656') and
                  (n.endswith('.ppst') or '.ppst.' in n))


def is_stock(ram, eboot):
    for fva, want in STOCK_WORDS.items():
        got = struct.unpack_from('<I', ram, MOD_OFF + fva)[0]
        on_disk = struct.unpack_from('<I', eboot, SEG + fva)[0]
        if on_disk != want:
            raise SystemExit('stock EBOOT does not hold 0x%08X at fva %#x '
                             '(wrong/other-version EBOOT?)' % (want, fva))
        if got != want:
            return False, fva, got
    return True, None, None


def build_diff(ram, eboot):
    """{fva: RAM word} for every word that differs between file and RAM."""
    diff = {}
    for i in range(0, len(eboot) - SEG, 4):
        if eboot[SEG + i:SEG + i + 4] != ram[MOD_OFF + i:MOD_OFF + i + 4]:
            diff[i] = struct.unpack_from('<I', ram, MOD_OFF + i)[0]
    return diff


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--state', help='stock-build save state or raw RAM dump')
    ap.add_argument('--eboot', default=os.path.join(
        paths.ROOT, 'EBOOT_USA_decrypted.bin'))
    ap.add_argument('--out', default='superset.pkl')
    ap.add_argument('--write', action='store_true',
                    help='dump the derived superset (never the tracked file)')
    args = ap.parse_args(argv)

    from chapter_voice_census import extract_ram

    if not os.path.isfile(args.eboot):
        raise SystemExit('missing decrypted stock EBOOT: %s' % args.eboot)
    eboot = open(args.eboot, 'rb').read()

    candidates = [args.state] if args.state else default_states()
    if not candidates:
        raise SystemExit('no candidate states; pass --state PATH '
                         '(set SN5_PPSSPP_MEMSTICK for the default search)')

    diff, used = None, None
    for path in candidates:
        ram = extract_ram(path)
        ok, fva, got = is_stock(ram, eboot)
        if not ok:
            print('skip %-30s patched build (fva %#x = 0x%08X)'
                  % (os.path.basename(path), fva, got))
            del ram
            continue
        diff = build_diff(ram, eboot)
        used = os.path.basename(path)
        print('stock state %-28s %d differing word(s)' % (used, len(diff)))
        del ram
        break
    if diff is None:
        raise SystemExit('no stock-build state found among %d candidate(s); '
                         'boot the STOCK USA build and write a state'
                         % len(candidates))

    if os.path.isfile(TRACKED):
        old = pickle.loads(open(TRACKED, 'rb').read())
        miss = sorted(set(old) - set(diff))
        print('vs tracked: tracked=%d derived=%d derived-only=%d tracked-only=%d'
              % (len(old), len(diff), len(set(diff) - set(old)), len(miss)))
        if miss:
            print('  tracked-only sample: %s' % [hex(x) for x in miss[:5]])
        print('  (derived is a superset: safe, but the tracked set is tighter '
              'and is the one the tooling uses)')
    else:
        print('tracked set %s missing - restore it from git history'
              % TRACKED)

    if args.write:
        if os.path.abspath(args.out) == os.path.abspath(TRACKED):
            raise SystemExit('refusing to overwrite the tracked set; restore '
                             'it with git checkout instead')
        with open(args.out, 'wb') as f:
            pickle.dump(diff, f)
        print('wrote %s (%d entries, from %s)' % (args.out, len(diff), used))
    else:
        print('no file written (pass --write to dump the superset)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
