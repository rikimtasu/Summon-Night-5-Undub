"""Summon Night 5 (USA) undub v2.

v2 = v1 (JP story/battle voice archive swap) + USA EBOOT engine patch:
the slot-65 (key 0x4041 = story-voice) handler at fva 0x1787C contains a
localization-added clamp that forces every voice id < 0x9088 (37000) to -1
(idle), which silences all story voices. JP's story voice ids are 36000-36835,
so this clamp kills exactly the whole story-voice id space.

Patch: NOP 3 instructions in the handler:
    0x17904  sltu  a1, s0, a1        (0x0205282B)
    0x17908  bnel  a1, zero, 0x17910 (0x54A00001)
    0x1790C  addiu s0, zero, -1      (0x2410FFFF)  <- delay slot, must go too

Build steps:
  1. copy+NOP the decrypted USA EBOOT -> work/EBOOT_USA_patched.bin
  2. v1 pipeline: add JP SV00-17.DAT over the USA ISO -> output ISO
  3. raw-overwrite the output ISO's /PSP_GAME/SYSDIR/EBOOT.BIN extent
     (same size, 3018032 bytes) with the patched plain ELF
"""
from pycdlib import PyCdlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths
from common import HashSink as _HashSink

USER_ISO_NAME = 'Summon Night 5 (USA).iso'
OUT_ISO_NAME = 'Summon Night 5 (USA) Undub.iso'

ROOT = paths.ROOT
WORK = paths.WORK                 # tracked tables + derived artifacts

USA_ISO = os.path.join(paths.ROOT, USER_ISO_NAME)
OUT_ISO = os.path.join(paths.ROOT, OUT_ISO_NAME)
SVDIR = paths.JPSV_DIR
SRC_EBOOT = os.path.join(paths.ROOT, 'EBOOT_USA_decrypted.bin')
PATCHED_EBOOT = os.path.join(paths.WORK, 'EBOOT_USA_patched.bin')

SEG = 0xC0  # ELF text vaddr base (file offset = fva + SEG)
PATCH_FVAS = (0x17904, 0x17908, 0x1790C)
EXPECT_WORDS = (0x0205282B, 0x54A00001, 0x2410FFFF)


def make_patched_eboot():
    d = bytearray(open(SRC_EBOOT, 'rb').read())
    for fva, exp in zip(PATCH_FVAS, EXPECT_WORDS):
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'word at fva {fva:#x} = {cur:#x}, expected {exp:#x}'
        d[off:off + 4] = b'\x00\x00\x00\x00'
    with open(PATCHED_EBOOT, 'wb') as f:
        f.write(d)
    print(f'patched EBOOT written: {PATCHED_EBOOT} ({len(d)} bytes)')


def swap_voice_archives():
    iso = PyCdlib()
    print('opening USA ISO...', flush=True)
    iso.open(USA_ISO)
    open_fps = []
    for i in range(18):
        name = f'SV{i:02d}.DAT'
        src = os.path.join(SVDIR, name)
        assert os.path.exists(src), src
        print(f'adding {name}...', flush=True)
        # add_fp keeps the fp until iso.write() -- do not close early
        fp = open(src, 'rb')
        open_fps.append(fp)
        iso.add_fp(fp, os.path.getsize(src), iso_path=f'/PSP_GAME/USRDIR/{name}')
    print('writing ISO (v1 stage)...', flush=True)
    if os.path.exists(OUT_ISO):
        os.remove(OUT_ISO)
    iso.write(OUT_ISO)
    iso.close()
    for fp in open_fps:
        fp.close()
    print('v1 stage done', flush=True)


def patch_eboot_extent():
    iso = PyCdlib()
    iso.open(OUT_ISO)
    extent = length = None
    for rec in iso.list_children(iso_path='/PSP_GAME/SYSDIR'):
        ident = rec.file_identifier().decode('latin-1').rstrip(';1').rstrip('.')
        if ident == 'EBOOT.BIN':
            extent = rec.extent_location()
            length = rec.get_data_length()
            break
    iso.close()
    assert extent is not None, 'EBOOT.BIN not found'
    patched = open(PATCHED_EBOOT, 'rb').read()
    print(f'EBOOT.BIN extent sector {extent} (byte {extent * 2048:#x}), length {length}')
    assert length == len(patched), f'size mismatch {length} vs {len(patched)}'
    with open(OUT_ISO, 'r+b') as f:
        f.seek(extent * 2048)
        f.write(patched)
    # verify
    with open(OUT_ISO, 'rb') as f:
        f.seek(extent * 2048)
        head = f.read(4)
        f.seek(extent * 2048 + SEG + 0x17904)
        words = struct.unpack('<3I', f.read(12))
    assert head == b'\x7fELF', f'EBOOT extent head = {head!r}'
    assert words == (0, 0, 0), f'patch words = {tuple(hex(w) for w in words)}'
    print('EBOOT extent verified: plain ELF, clamp instructions NOPed')
    assert_jp_opening_present()


# The EBOOT-only rebuild path (build_v4fix / build_v6fix -> patch_eboot_extent)
# rewrites just the EBOOT extent, so it silently INHERITS whatever 04.DAT the
# current OUT_ISO happens to hold.  A full rebuild regenerates OUT_ISO from the
# stock USA ISO, which drops the JP opening; nothing noticed, and the shipped
# patch ended up with JP voices but the USA opening.  So assert it here, at the
# exact step where the assumption used to be made.  v5 verified this once; an
# EBOOT-only rebuild never re-checked it.
JP04_SHA = '97feeed3059f2baf'          # JP ISO 04.DAT, first 8 bytes of sha256
USA04_SHA = 'b063121c47f10c56'          # stock USA 04.DAT


def assert_jp_opening_present(strict=True):
    """Confirm OUT_ISO carries the JP opening, not the stock USA one."""
    try:
        from pycdlib import PyCdlib
    except ImportError:
        print('SKIP opening check: pycdlib unavailable')
        return None
    iso = PyCdlib()
    try:
        iso.open(OUT_ISO)
        sink = _HashSink()
        iso.get_file_from_iso_fp(sink, iso_path='/PSP_GAME/USRDIR/04.DAT')
        h = sink.hexdigest()
    finally:
        try:
            iso.close()
        except Exception:
            pass
    jp = h.startswith(JP04_SHA)
    usa = h.startswith(USA04_SHA)
    if jp:
        print('opening check: 04.DAT == JP OK')
    elif usa:
        msg = ('opening check FAILED: 04.DAT is the STOCK USA opening, not JP.\n'
               '    A full rebuild regenerated OUT_ISO and dropped the v5 JP\n'
               '    opening swap. Re-apply it (see apply_jp_opening.py) or run\n'
               '    build_v5.rebuild_iso() before shipping.')
        if strict:
            raise AssertionError(msg)
        print(msg)
    else:
        msg = 'opening check FAILED: 04.DAT matches neither JP nor stock USA'
        if strict:
            raise AssertionError(msg)
        print(msg)
    return jp


if __name__ == '__main__':
    make_patched_eboot()
    swap_voice_archives()
    patch_eboot_extent()
    print('done:', OUT_ISO)
