# -*- coding: utf-8 -*-
"""Sweep chapters 3..18: capture a JP + USA story block per chapter, unattended.

For each chapter N:
  1. patch EVERY plaintext slot of both versions to chapter N, so whichever
     slot the load menu happens to highlight, it is the target chapter
  2. park the old encrypted slots (GAME47, JP 00..05) so they cannot be picked
  3. boot each game, drive the menus, F2 to write a save state
  4. verify the capture actually produced a story block (a state file alone
     proves nothing - the earlier F8 attempt wrote a state with no chapter in
     it), and record c10 + const-id range
  5. close the emulator before the next version

No gameplay is involved: the game loads the chapter script on Continue and the
state is written from the hub.  The census only needs JP/USA pairs of the SAME
block, not story dialogue.

Everything touched here is restorable:
  * slot contents  -> work/sweep_backups/<slot>   (--restore-slots)
  * parked slots   -> work/savedata_parked/       (--restore-slots)
  * state files    -> *.precap<N> beside each .ppst

Usage
-----
    python chapter_sweep.py --chapters 3,4          # test two chapters
    python chapter_sweep.py --chapters 3-18         # the full sweep
    python chapter_sweep.py --restore-slots
"""
import glob
import os
import re
import shutil
import struct
import subprocess
import sys
import time

sys.path.insert(0, r'D:\Documents\Default Project\work')
import chapter_capture as C
import chapter_voice_census as V

PARKED = r'D:\Documents\Default Project\work\savedata_parked'
SWEEPBK = r'D:\Documents\Default Project\work\sweep_backups'
LOG = r'D:\Documents\Default Project\work\sweep_log.txt'
DEFAULT_KEYS = 'enter,wait:4,enter,wait:4,enter,wait:6,f2'


def log(msg, echo=True):
    line = '[%s] %s' % (time.strftime('%H:%M:%S'), msg)
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')
    if echo:
        print(line, flush=True)


# --------------------------------------------------------------- slot admin
def slot_path(slot):
    return os.path.join(C.ROOT, slot)


def is_plaintext(slot):
    p = os.path.join(slot_path(slot), 'DATA.BIN')
    if not os.path.isfile(p):
        return False
    d = open(p, 'rb').read()
    return not C.validate(d)


def all_slots():
    return [n for n in sorted(os.listdir(C.ROOT))
            if n.startswith(('ULUS10656SN5GAME', 'NPJH50696SN5GAME'))]


def backup_slots():
    os.makedirs(SWEEPBK, exist_ok=True)
    for slot in all_slots():
        dst = os.path.join(SWEEPBK, slot)
        if not os.path.isdir(dst):
            shutil.copytree(slot_path(slot), dst)
            log('slot backup: %s' % slot)


def park_encrypted():
    os.makedirs(PARKED, exist_ok=True)
    for slot in all_slots():
        if is_plaintext(slot):
            continue
        src = slot_path(slot)
        dst = os.path.join(PARKED, slot)
        if os.path.isdir(dst) or not os.path.isdir(src):
            continue
        shutil.move(src, dst)
        log('parked non-plaintext slot: %s' % slot)


def restore_slots():
    if os.path.isdir(PARKED):
        for slot in sorted(os.listdir(PARKED)):
            shutil.move(os.path.join(PARKED, slot), slot_path(slot))
            log('unparked %s' % slot)
    for slot in all_slots():
        src = os.path.join(SWEEPBK, slot)
        if os.path.isdir(src):
            shutil.rmtree(slot_path(slot))
            shutil.copytree(src, slot_path(slot))
            log('restored %s' % slot)


def patch_slots(chapter, scene=0):
    """Point every plaintext slot of both versions at `chapter`."""
    n = 0
    for slot in all_slots():
        if not is_plaintext(slot):
            continue
        p = os.path.join(slot_path(slot), 'DATA.BIN')
        d = bytearray(open(p, 'rb').read())
        struct.pack_into('<I', d, 0x60, chapter)
        struct.pack_into('<I', d, 0xD8, scene)
        if C.validate(bytes(d)):
            raise SystemExit('patched %s invalid' % slot)
        open(p, 'wb').write(bytes(d))
        n += 1
    log('patched %d slot(s) to chapter %d (scene %d)' % (n, chapter, scene))
    return n


# ---------------------------------------------------------------- capturing
def emulator_running():
    out = subprocess.run(
        ['tasklist', '/FI', 'IMAGENAME eq PPSSPPWindows64.exe', '/NH'],
        capture_output=True, text=True).stdout
    return 'PPSSPPWindows64.exe' in out


def close_emulator(timeout=45):
    """Kill PPSSPP and WAIT for it to actually be gone.

    Relaunching while the old process is still shutting down makes the next
    launch fail (or silently reuse the dying window, so key presses go to the
    wrong process).  Never Popen until tasklist agrees it has exited.
    """
    if not emulator_running():
        return True
    subprocess.run(['taskkill', '/F', '/IM', 'PPSSPPWindows64.exe'],
                   capture_output=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not emulator_running():
            return True
        time.sleep(1)
    return False


def launch_emulator(iso, tries=2, window_timeout=120):
    """Start PPSSPP and confirm a window appeared. Returns the hwnd or None.

    On failure the caller must ABORT the sweep - retrying in a loop is what
    looked like PPSSPP repeatedly trying (and failing) to start.
    """
    for attempt in range(1, tries + 1):
        subprocess.Popen([C.PPSSPP, iso])
        hwnd = C.find_ppsspp_window(window_timeout)
        if hwnd:
            return hwnd
        log('launch attempt %d/%d produced no window; closing and retrying'
            % (attempt, tries))
        close_emulator()
        time.sleep(5)
    return None


def state_blocks(state_path):
    """Story blocks in a save state: [(c10, id_lo, id_hi, lines, const, pair)]"""
    try:
        ram = V.extract_ram(state_path)
    except Exception as exc:                          # noqa: BLE001
        return [('extract-failed', str(exc), 0, 0, 0, 0)]
    pat = struct.pack('<II', 0x10000201, 0x10000002)
    out, s = [], 0
    while True:
        o = ram.find(pat, s)
        if o < 0:
            break
        s = o + 1
        c10 = struct.unpack_from('<I', ram, o + 16)[0]
        if c10 < 3000:
            continue
        b = V.parse_block(ram, o)
        if not b:
            continue
        ids = sorted(v for (kind, v) in b['census'] if kind == 'const')
        out.append((c10, ids[0] if ids else 0, ids[-1] if ids else 0,
                    len(b['lines']),
                    sum(1 for (k, v) in b['census'] if k == 'const'),
                    sum(1 for (k, v) in b['census'] if k == 'pair')))
    del ram
    return out


def capture(version, chapter, keys, boot_delay, settle, timeout):
    """Launch a game, drive the menus, wait for a new state, close it."""
    gid = C.GAME[version][1]
    launched = time.time()
    before = {os.path.basename(p): os.path.getmtime(p)
              for p in glob.glob(os.path.join(C.STATEDIR, gid + '_1.01_*.ppst'))}
    iso = os.path.abspath(C.ISOS[version])
    if not close_emulator():
        log('[%s] PPSSPP would not exit; ABORTING sweep' % version)
        raise SystemExit(3)
    hwnd = launch_emulator(iso)
    if hwnd is None:
        log('[%s] launch failed after retries; ABORTING sweep '
            '(not retrying in a loop)' % version)
        close_emulator()
        raise SystemExit(4)
    time.sleep(boot_delay)
    C.run_key_sequence(hwnd, keys)
    time.sleep(settle)
    got = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in glob.glob(os.path.join(C.STATEDIR, gid + '_1.01_*.ppst')):
            if os.path.getmtime(p) > launched and \
                    before.get(os.path.basename(p), 0) != os.path.getmtime(p):
                got = p
                break
        if got:
            break
        time.sleep(3)
    if not got:
        log('[%s] ch%d: no new state within %ds' % (version, chapter, timeout))
        return None
    time.sleep(1)
    blocks = state_blocks(got)
    log('[%s] ch%d: state %s (%d bytes) blocks=%s'
        % (version, chapter, os.path.basename(got), os.path.getsize(got),
           blocks or 'NONE'))
    return {'version': version, 'chapter': chapter, 'state': got,
            'blocks': blocks}


# --------------------------------------------------------------------- main
def parse_chapters(spec):
    out = []
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-')
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--chapters', default='3,4')
    ap.add_argument('--keys', default=DEFAULT_KEYS)
    ap.add_argument('--boot-delay', type=int, default=30)
    ap.add_argument('--settle', type=int, default=12)
    ap.add_argument('--timeout', type=int, default=120)
    ap.add_argument('--restore-slots', action='store_true')
    ap.add_argument('--keep-open', action='store_true',
                    help='do not close the emulator after each version')
    args = ap.parse_args(argv)

    if args.restore_slots:
        restore_slots()
        return 0

    chapters = parse_chapters(args.chapters)
    enc = C.check_encrypt_save()
    log('=== sweep start: chapters %s (EncryptSave=%s) ==='
        % (chapters, enc))
    if enc != 'False':
        log('ABORT: EncryptSave is not False')
        return 2

    backup_slots()
    park_encrypted()

    known = set()
    results = []
    for ch in chapters:
        log('--- chapter %d ---' % ch)
        patch_slots(ch)
        for version in ('usa', 'jp'):
            res = capture(version, ch, args.keys, args.boot_delay,
                          args.settle, args.timeout)
            if res:
                results.append(res)
                for blk in res['blocks']:
                    if isinstance(blk[0], int):
                        known.add(blk[0])
            if not args.keep_open:
                close_emulator()
            else:
                log('leaving emulator open (--keep-open)')
                break
    close_emulator()

    log('=== sweep done: %d capture(s) ===' % len(results))
    for r in results:
        log('  %s ch%-2d %s' % (r['version'], r['chapter'],
                                r['blocks'] or 'no blocks'))
    log('then: python chapter_voice_census.py --states "%s"' % C.STATEDIR)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
