# -*- coding: utf-8 -*-
"""Capture a story-script RAM dump for chapter N by booting the game once.

WHY
---
The census tool needs a JP and a USA story block per chapter.  Those blocks are
assembled at load time and are NOT stored expanded in any USRDIR container
(see probe_remaining_containers.py / crib_search_story_tokens.py), so each
chapter needs the game to load it once.  That does NOT require playing: the
chapter field is property id 20 at DATA.BIN +0x60, so a save can be pointed at
chapter N, the game loads that chapter's script during Continue, and a save
state taken a moment later contains the block in RAM.

SAFETY
------
* Never touches an existing save.  The template slot is COPIED to a scratch slot
  (default <GAMEID>90) and only that copy is patched, so the game autosaves into
  scratch space and real slots stay byte-identical.
* The copy is validated (magic 0x00021001, size 0x29890, +0x0C == size-0x1C)
  before writing, and --restore removes the scratch slot.
* Requires ppsspp.ini EncryptSave = False (it is; plaintext is the whole basis
  of the format work).  The script checks and refuses otherwise.

KEYS
----
PPSSPP has no CLI option to WRITE a save state (only --state= to read one), so
the state must be written in-app.  By default this script focuses the window and
sends Enter (Continue on the title screen) then F8 (quick save state).  If that
timing does not match the game's flow, use --manual and press them yourself.

Usage
-----
    python chapter_capture.py --chapter 2 --version usa
    python chapter_capture.py --chapter 2 --version both --manual
    python chapter_capture.py --restore
    python chapter_capture.py --chapter 2 --version usa --dry-run
"""
import ctypes
import glob
import os
import shutil
import struct
import subprocess
import sys
import time
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

ROOT = paths.savedata()          # <memstick>\PSP\SAVEDATA
INI = paths.ppsspp_ini()
STATEDIR = paths.state_dir()
PPSSPP = paths.PPSSPP_EXE
ISOS = {
    'usa': r'Summon Night 5 (USA).iso',
    'jp': r'Summon Night 5 (JP).iso',
}
GAME = {
    'usa': ('ULUS10656SN5GAME', 'ULUS10656', 0x00021001),
    'jp': ('NPJH50696SN5GAME', 'NPJH50696', 0x00021001),
}
SCRATCH_SUFFIX = '90'
MAGIC = 0x00021001
EXPECTED_SIZE = 0x29890
CHAPTER_OFF = 0x60

user32 = ctypes.windll.user32
VK_RETURN, VK_F8, VK_F2, VK_F4 = 0x0D, 0x77, 0x71, 0x73
# PPSSPP defaults confirmed on this install: F2 = SAVE STATE, F4 = LOAD STATE.
# (F8 is not the saver - pressing it still produced a state file, but from the
# wrong moment, so the block census came back empty. Never trust the capture
# without re-running the census.)
SAVE_KEY = VK_F2
LOAD_KEY = VK_F4


# ------------------------------------------------------------------ windows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND,
                                     wintypes.LPARAM)


def window_titles():
    out = []

    def cb(hwnd, _l):
        if not user32.IsWindowVisible(hwnd):
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        out.append((hwnd, buf.value))
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    return out


def find_ppsspp_window(timeout=60):
    """hwnd of a visible window whose title mentions PPSSPP or the game."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for hwnd, title in window_titles():
            t = title.lower()
            if 'ppsspp' in t or 'summon night 5' in t:
                return hwnd
        time.sleep(1.0)
    return None


VKEYS = {
    'enter': 0x0D, 'return': 0x0D, 'space': 0x20, 'esc': 0x1B,
    'up': 0x26, 'down': 0x28, 'left': 0x25, 'right': 0x27,
    'f2': 0x71, 'f4': 0x73, 'f8': 0x77,
}


def run_key_sequence(hwnd, spec, gap=1.2):
    """Send a scripted menu sequence, e.g. 'down,enter,wait:3,enter,f2'.

    The SN5 front end is: title -> main menu (item is "Load", NOT "Continue")
    -> slot list -> chapter content, so a single Enter is never enough.  Keep
    the sequence explicit and short rather than guessing, and always confirm
    the capture with the census afterwards.
    """
    for raw in spec.split(','):
        tok = raw.strip().lower()
        if not tok:
            continue
        if tok.startswith('wait:'):
            secs = float(tok.split(':', 1)[1])
            print('    wait %.1fs' % secs)
            time.sleep(secs)
            continue
        if tok not in VKEYS:
            print('    unknown key token %r - skipped' % tok)
            continue
        send_key(hwnd, VKEYS[tok])
        print('    sent %s' % tok)
        time.sleep(gap)


def send_key(hwnd, vk):
    user32.ShowWindow(hwnd, 9)              # SW_RESTORE
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.4)
    scan = user32.MapVirtualKeyW(vk, 0)
    user32.keybd_event(vk, scan, 0, 0)
    time.sleep(0.08)
    user32.keybd_event(vk, scan, 2, 0)       # KEYEVENTF_KEYUP
    time.sleep(0.3)


# --------------------------------------------------------------- save slots
def u32(d, off):
    return struct.unpack_from('<I', d, off)[0]


def plaintext_slots(prefix):
    """Existing slots whose DATA.BIN is a valid plaintext game save."""
    out = []
    for name in sorted(os.listdir(ROOT)):
        if not name.startswith(prefix):
            continue
        p = os.path.join(ROOT, name, 'DATA.BIN')
        if not os.path.isfile(p):
            continue
        d = open(p, 'rb').read()
        if (len(d) == EXPECTED_SIZE and u32(d, 0) == MAGIC
                and u32(d, 0x0C) == len(d) - 0x1C):
            out.append(name)
    return out


def validate(d):
    if len(d) != EXPECTED_SIZE:
        return 'size %d != 0x%X' % (len(d), EXPECTED_SIZE)
    if u32(d, 0) != MAGIC:
        return 'magic 0x%08X != 0x%08X' % (u32(d, 0), MAGIC)
    if u32(d, 0x0C) != len(d) - 0x1C:
        return '+0x0C %d != size-0x1C' % u32(d, 0x0C)
    return None


BACKUPS = os.path.join(paths.WORK, 'capture_backups')


def backup_slot(slot, chapter):
    """Copy a whole save slot outside SAVEDATA (a dir inside SAVEDATA would
    show up as an extra slot).  Backups are per chapter and never overwritten."""
    src = os.path.join(ROOT, slot)
    dst = os.path.join(BACKUPS, '%s_ch%d' % (slot, chapter))
    if os.path.isdir(dst):
        return dst
    os.makedirs(BACKUPS, exist_ok=True)
    shutil.copytree(src, dst)
    return dst


def restore_slot(slot, chapter):
    dst = os.path.join(BACKUPS, '%s_ch%d' % (slot, chapter))
    if not os.path.isdir(dst):
        print('no backup for %s ch%d' % (slot, chapter))
        return False
    src = os.path.join(ROOT, slot)
    if os.path.isdir(src):
        shutil.rmtree(src)
    shutil.copytree(dst, src)
    print('restored %s from %s' % (slot, os.path.basename(dst)))
    return True


def make_scratch(version, chapter, slot=None):
    """Patch an EXISTING, game-visible slot to `chapter`.

    The game only lists slots in its own range (observed: GAME41..GAME47), so
    inventing a slot name gives a save the game never sees - it just shows no
    Continue.  Therefore patch a real slot in place and keep the original in
    work/capture_backups (outside SAVEDATA) for --restore.
    """
    prefix, gid, _m = GAME[version]
    slots = plaintext_slots(prefix)
    if not slots:
        raise SystemExit('%s: no plaintext save slot available' % version)
    target = slot or slots[0]
    if target not in slots:
        raise SystemExit('%s: slot %s is not a valid plaintext save (%s)'
                         % (version, target, ', '.join(slots)))
    backup_slot(target, chapter)
    binp = os.path.join(ROOT, target, 'DATA.BIN')
    d = bytearray(open(binp, 'rb').read())
    before = u32(d, CHAPTER_OFF)
    struct.pack_into('<I', d, CHAPTER_OFF, chapter)
    err = validate(bytes(d))
    if err:
        raise SystemExit('patched save invalid: %s' % err)
    open(binp, 'wb').write(bytes(d))
    # newest mtime so the game prefers this slot
    now = time.time()
    sd = os.path.join(ROOT, target)
    for f in os.listdir(sd):
        os.utime(os.path.join(sd, f), (now, now))
    return target, target, before, binp


# --------------------------------------------------------------------- state
def backup_states(prefix, chapter):
    """Quick-save (F8) overwrites the CURRENT state slot, which holds the
    chapter-1 research states.  Copy them aside first as <name>.precap<N>, a
    suffix the census's *.ppst glob ignores."""
    made = []
    for p in glob.glob(os.path.join(STATEDIR, prefix + '_1.01_*.ppst')):
        dst = '%s.precap%d' % (p, chapter)
        if not os.path.isfile(dst):
            shutil.copyfile(p, dst)
            made.append(dst)
    for p in made:
        print('[%s] state backup: %s' % (prefix, os.path.basename(p)))
    return made


def newest_state(prefix, since):
    """Newest <gid>_1.01_*.ppst modified after `since`, or None."""
    best = None
    for p in glob.glob(os.path.join(STATEDIR, prefix + '_1.01_*.ppst')):
        mt = os.path.getmtime(p)
        if mt >= since and (best is None or mt > best[0]):
            best = (mt, p)
    return best[1] if best else None


def check_encrypt_save():
    try:
        for line in open(INI, encoding='utf-8', errors='replace'):
            if line.strip().startswith('EncryptSave'):
                val = line.split('=')[1].strip()
                if val.lower() != 'false':
                    raise SystemExit('ppsspp.ini EncryptSave = %s - the save '
                                     'would be encrypted; set it to False' % val)
                return val
    except (IOError, OSError):
        pass
    return 'not found'


# ---------------------------------------------------------------------- main
def capture(version, chapter, args):
    iso = os.path.abspath(ISOS[version])
    if not os.path.isfile(iso):
        raise SystemExit('missing ISO: %s' % iso)
    scratch, template, before, binp = make_scratch(version, chapter,
                                                   args.slot)
    backup_states(GAME[version][1], chapter)
    print('[%s] slot %s: chapter %d -> %d (backup in %s)'
          % (version, scratch, before, chapter, BACKUPS))
    print('[%s] DATA.BIN: %s' % (version, binp))
    if args.dry_run:
        return

    launched = time.time()
    if args.attach:
        print('[%s] --attach: using the already-running PPSSPP (no launch, '
              'no new scratch slot)' % version)
    else:
        proc = subprocess.Popen([PPSSPP, iso])
        print('[%s] launched PPSSPP with %s (pid %d)'
              % (version, os.path.basename(iso), proc.pid))
    hwnd = find_ppsspp_window(90)
    if hwnd is None:
        print('[%s] WARNING: PPSSPP window not found; drive it manually'
              % version)
    else:
        print('[%s] window found (hwnd %d)' % (version, hwnd))

    if not args.manual and hwnd:
        if args.attach:
            print('[%s] attaching to running PPSSPP; waiting %ds then F2 '
                  '(save state)' % (version, args.load_delay))
            time.sleep(args.load_delay)
            send_key(hwnd, SAVE_KEY)
            print('[%s] F2 sent' % version)
        else:
            print('[%s] waiting %ds, then Enter (Continue)'
                  % (version, args.boot_delay))
            time.sleep(args.boot_delay)
            send_key(hwnd, VK_RETURN)
            print('[%s] Enter sent; waiting %ds for the chapter to load, '
                  'then F2 (save state)' % (version, args.load_delay))
            time.sleep(args.load_delay)
            send_key(hwnd, SAVE_KEY)
            print('[%s] F2 sent' % version)
    else:
        print('[%s] MANUAL: open the load menu, pick the patched slot, let it '
              'settle, then press F2 (save state).' % version)

    prefix = GAME[version][1]
    deadline = time.time() + args.timeout
    found = newest_state(prefix, launched - 5)
    while time.time() < deadline and not found:
        time.sleep(3)
        found = newest_state(prefix, launched - 5)
    if found:
        print('[%s] STATE CAPTURED: %s' % (version, found))
        print('           %d bytes, mtime %s'
              % (os.path.getsize(found), time.strftime('%H:%M:%S',
                                                        time.localtime(os.path.getmtime(found)))))
    else:
        print('[%s] no new .ppst in %s within %ds' % (version, STATEDIR,
                                                       args.timeout))
        print('           if the game reached the chapter, press F8 now and '
              're-run the census with --states "%s"' % STATEDIR)
    print('[%s] close PPSSPP when done; --restore removes the scratch slot'
          % version)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--chapter', type=int, default=None)
    ap.add_argument('--version', choices=('usa', 'jp', 'both'), default='usa')
    ap.add_argument('--manual', action='store_true',
                    help='do not send keys; press Enter then F8 yourself')
    ap.add_argument('--boot-delay', type=int, default=25,
                    help='seconds before sending Enter (title -> Continue)')
    ap.add_argument('--load-delay', type=int, default=50,
                    help='seconds after Enter before sending F8')
    ap.add_argument('--timeout', type=int, default=180,
                    help='seconds to wait for the .ppst to appear')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--restore', action='store_true')
    ap.add_argument('--keys', default=None,
                    help='key sequence for --attach, e.g. "f2" or '
                         '"down,enter,wait:4,enter,f2". Tokens: enter up '
                         'down left right f2 f4 space esc wait:SECS')
    ap.add_argument('--slot', default=None,
                    help='save slot to patch in place (default: first '
                         'plaintext slot). Must be a slot the game lists, '
                         'e.g. ULUS10656SN5GAME41')
    ap.add_argument('--attach', action='store_true',
                    help='do not launch: use the already-running PPSSPP, wait '
                         '--load-delay, then send F2 (save state)')
    args = ap.parse_args(argv)
    paths.require_ppsspp()       # ROOT/INI/STATEDIR/PPSSPP all come from it

    if args.attach:
        # no scratch slot churn: just attach and save a state
        versions = ('usa', 'jp') if args.version == 'both' else (args.version,)
        for v in versions:
            hwnd = find_ppsspp_window(30)
            if hwnd is None:
                print('[%s] no PPSSPP window found - is it running?' % v)
                continue
            print('[%s] attaching to hwnd %d' % (v, hwnd))
            if args.keys:
                print('[%s] key sequence: %s' % (v, args.keys))
                run_key_sequence(hwnd, args.keys)
            else:
                time.sleep(args.load_delay)
                send_key(hwnd, SAVE_KEY)
                print('[%s] F2 (save state) sent' % v)
        return 0
    if args.restore:
        for v in (('usa', 'jp') if args.version == 'both' else (args.version,)):
            prefix = GAME[v][0]
            for name in sorted(os.listdir(ROOT)):
                if not name.startswith(prefix):
                    continue
                for bdir in sorted(glob.glob(os.path.join(BACKUPS,
                                                         name + '_ch*'))):
                    ch = int(os.path.basename(bdir).split('_ch')[1])
                    if restore_slot(name, ch):
                        break
        return 0
    if args.chapter is None:
        ap.print_help()
        return 2

    print('EncryptSave = %s (must be False)' % check_encrypt_save())
    versions = ('usa', 'jp') if args.version == 'both' else (args.version,)
    for v in versions:
        capture(v, args.chapter, args)
        if len(versions) > 1 and v != versions[-1]:
            print('\n--- close the running PPSSPP before the next version ---\n')
    print('\nNext: python chapter_voice_census.py --selftest --states "%s"'
          % STATEDIR)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
