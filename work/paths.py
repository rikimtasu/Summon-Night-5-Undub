# -*- coding: utf-8 -*-
"""Central path resolution for the SN5 undub tooling.

WHY
---
The repo tracks the *model* files (`v3_entries.txt`, `extra_entries.txt`,
`usa_loader_diff.pkl`) but NOT the game artifacts (ISOs, decrypted EBOOTs,
`JP04.DAT`, JP voice archives, save states).  Those live in whatever directory
the user keeps them in.  Every script resolves paths through here instead of
hard-coding the maintainer's checkout, so any clone works:

    SN5_ROOT                directory holding the artifacts AND a work/ dir
                            with the model files.  Defaults to this checkout's
                            repo root (the parent of work/), which is correct
                            for a full checkout that also holds the ISOs.
    SN5_JPSV_DIR            directory holding the JP SV00-17.DAT archives
                            (default: <SN5_ROOT>/work/JPSV/PSP_GAME/USRDIR)
    SN5_PPSSPP_MEMSTICK     PPSSPP memstick dir (the one containing PSP/).
                            Needed only by the capture/sweep/save-editor tools.
    SN5_PPSSPP_EXE          PPSSPP executable (default: PPSSPPWindows64.exe
                            next to the memstick dir)

Example (run the tracked code from a checkout that holds no game files,
against an artifact tree elsewhere):

    set SN5_ROOT=D:\\Documents\\Default Project
    set SN5_PPSSPP_MEMSTICK=D:\\Video_Game\\Emulator\\PSP\\PPSSPP 1.20\\ppsspp\\memstick
    python work\\verify_shipped_patch.py
"""
import os
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))          # ...\work
REPO_ROOT = os.path.dirname(HERE)                          # repo checkout

ROOT = os.path.abspath(os.environ.get('SN5_ROOT') or REPO_ROOT)
WORK = os.path.join(ROOT, 'work')

JPSV_DIR = os.environ.get('SN5_JPSV_DIR') or os.path.join(
    WORK, 'JPSV', 'PSP_GAME', 'USRDIR')

PPSSPP_MEMSTICK = os.environ.get('SN5_PPSSPP_MEMSTICK') or ''
PPSSPP_EXE = os.environ.get('SN5_PPSSPP_EXE') or (
    os.path.join(os.path.dirname(PPSSPP_MEMSTICK), 'PPSSPPWindows64.exe')
    if PPSSPP_MEMSTICK else '')


def memstick(*parts):
    """Path inside the PPSSPP memstick, or '' when SN5_PPSSPP_MEMSTICK unset."""
    return os.path.join(PPSSPP_MEMSTICK, *parts) if PPSSPP_MEMSTICK else ''


def savedata():
    return memstick('PSP', 'SAVEDATA')


def ppsspp_ini():
    return memstick('PSP', 'SYSTEM', 'ppsspp.ini')


def state_dir():
    return memstick('PSP', 'PPSSPP_STATE')


def require_ppsspp():
    if not PPSSPP_MEMSTICK:
        raise SystemExit(
            'SN5_PPSSPP_MEMSTICK is not set (needed for save-state capture, '
            'the chapter sweep and the save editor); see work/paths.py')
    return PPSSPP_MEMSTICK


def scratch_dir(name):
    """Per-run scratch directory outside the repo (never a hard-coded path)."""
    return tempfile.mkdtemp(prefix=name + '_')
