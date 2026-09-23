"""Summon Night 5 (USA) undub v5 = v4 + JP opening movie.

v4: JP SV00-17 + EBOOT (clamp NOPs + split voice hook).
v5 adds: JP 04.DAT (single-PSMF opening movie) over USA 04.DAT.
EBOOT patch unchanged (reuse current EBOOT_USA_patched.bin).
"""
import os
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
from pycdlib import PyCdlib
import build_undub_v2 as v2

USA_ISO = v2.USA_ISO
OUT_ISO = v2.OUT_ISO
SVDIR = v2.SVDIR
JP04 = r'D:\Documents\Default Project\work\JP04.DAT'


def rebuild_iso():
    iso = PyCdlib()
    print('opening USA ISO...', flush=True)
    iso.open(USA_ISO)
    fps = []
    for i in range(18):
        name = f'SV{i:02d}.DAT'
        src = os.path.join(SVDIR, name)
        fp = open(src, 'rb')
        fps.append(fp)
        iso.add_fp(fp, os.path.getsize(src), iso_path=f'/PSP_GAME/USRDIR/{name}')
        print(f'added {name}', flush=True)
    fp = open(JP04, 'rb')
    fps.append(fp)
    iso.rm_file(iso_path='/PSP_GAME/USRDIR/04.DAT')
    iso.add_fp(fp, os.path.getsize(JP04), iso_path='/PSP_GAME/USRDIR/04.DAT')
    print('replaced with JP 04.DAT (opening)', flush=True)
    if os.path.exists(OUT_ISO):
        os.remove(OUT_ISO)
    print('writing ISO...', flush=True)
    iso.write(OUT_ISO)
    iso.close()
    for fp in fps:
        fp.close()
    print('rebuild done', flush=True)


def verify():
    iso = PyCdlib()
    iso.open(OUT_ISO)
    with iso.open_file_from_iso(iso_path='/PSP_GAME/USRDIR/04.DAT') as f:
        o04 = f.read()
    with iso.open_file_from_iso(iso_path='/PSP_GAME/SYSDIR/EBOOT.BIN') as f:
        feb = f.read(16)
    n = 0
    for rec in iso.list_children(iso_path='/PSP_GAME/USRDIR'):
        ident = rec.file_identifier().decode('latin-1').rstrip(';1').rstrip('.')
        if ident.startswith('SV'):
            n += 1
    iso.close()
    jp04 = open(JP04, 'rb').read()
    assert o04 == jp04, 'output 04.DAT != JP 04.DAT!'
    print(f'04.DAT verified JP ({len(o04)} bytes), SV files: {n}, EBOOT head: {feb.hex()}')
    # EBOOT extent still patched (hook word)
    with open(OUT_ISO, 'rb') as f:
        import struct
        f.seek(1615 * 2048 + 0xC0 + 0x17848)
        hw = struct.unpack('<I', f.read(4))[0]
    assert hw == 0x0A28A21A, f'hook word = {hw:#x}'
    print('EBOOT hook intact')


if __name__ == '__main__':
    rebuild_iso()
    v2.patch_eboot_extent()
    verify()
    print('done:', OUT_ISO)
