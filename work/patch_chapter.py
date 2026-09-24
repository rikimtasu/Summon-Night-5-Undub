# -*- coding: utf-8 -*-
"""Set the chapter field in a plaintext Summon Night 5 DATA.BIN.

Chapter is property id 20, and property[i] lives at file offset 0x10 + i*4,
so chapter = 0x10 + 20*4 = 0x60. The chain proving this is in RE_notes.md:

    0x1A996C(obj,id) = *(obj->array + id*4)
    loader 0x141544  = *(s_pLoadGameData + 0x10 + i*4), 230 words
    0x141CE0         memcpy(s_pLoadGameData, param+0xC680, 0x29890)  = whole file
    0x14736C get(0x88494, 20) -> index 0x23311C "Ch. N, <title>"
    same wrapper 0x87E30+0x664 = 0x88494 in both loader and description fn

Valid chapter ids come from that 34-entry table:

      0 First Dream                       8 Academy Defense
      1 Border City Savorle               9 The Price of Aspiration
      2 What Have You Forgotten?         10 Ribbons of Chain
      3 Another Sunny Day in Savorle     11 Festering Darkness
      4 Nostalgic Schoolhouse            12 Shades of Grey
      5 Connected Hearts, Resonant Souls 13 Myriad Black Tentacles
      6 Bizarre Summon Arts              14 Dreaming of Tomorrow Today
      7 Doubt and Guidance               15 Just Once More, Like Before
     16 Ending   17 Karma   18 Clear Data

Usage:
    python patch_chapter.py <SAVEDATA-subdir> <chapter>   # backups then patches
    python patch_chapter.py <SAVEDATA-subdir> --restore   # put the backup back

The backup is written beside DATA.BIN as DATA.BIN.chapbak, so it travels with
the save and a restore never depends on anything outside the save directory.
"""
import os
import shutil
import struct
import sys

ROOT = (r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick'
        r'\PSP\SAVEDATA')
CHAPTER_OFF = 0x60
BAK_SUFFIX = '.chapbak'
MAX_CHAPTER = 18

NAMES = {
    0: 'First Dream', 1: 'Border City Savorle', 2: 'What Have You Forgotten?',
    3: 'Another Sunny Day in Savorle', 4: 'Nostalgic Schoolhouse',
    5: 'Connected Hearts, Resonant Souls', 6: 'Bizarre Summon Arts',
    7: 'Doubt and Guidance', 8: 'Academy Defense',
    9: 'The Price of Aspiration', 10: 'Ribbons of Chain',
    11: 'Festering Darkness', 12: 'Shades of Grey',
    13: 'Myriad Black Tentacles', 14: 'Dreaming of Tomorrow Today',
    15: 'Just Once More, Like Before', 16: 'Ending', 17: 'Karma',
    18: 'Clear Data',
}


def paths(slot):
    d = os.path.join(ROOT, slot)
    return d, os.path.join(d, 'DATA.BIN'), os.path.join(d, 'DATA.BIN' + BAK_SUFFIX)


def describe(data, off=0x60):
    cur = struct.unpack_from('<I', data, off)[0]
    play = struct.unpack_from('<I', data, 8)[0]
    # show the property-array neighbourhood so a patch can be eyeballed
    ctx = ' '.join('%d=0x%X' % (i, struct.unpack_from('<I', data, 0x10 + i * 4)[0])
                   for i in range(18, 25))
    return cur, play, ctx


def main(argv):
    # accepts: <slot> [chapter] [--playtime frames] [--restore]
    restore = False
    playtime = None
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--restore':
            restore = True
        elif a == '--playtime':
            i += 1
            if i >= len(argv):
                print('--playtime needs a value')
                return 2
            playtime = int(argv[i], 0)
        elif a in ('-h', '--help'):
            print(__doc__)
            return 0
        else:
            pos.append(a)
        i += 1

    if not pos:
        print(__doc__)
        return 2
    slot = pos[0]
    _, binp, bakp = paths(slot)
    if not os.path.isfile(binp):
        print('no such save: %s' % binp)
        return 1

    data = bytearray(open(binp, 'rb').read())
    cur, play, ctx = describe(data)
    print('slot   : %s' % slot)
    print('size   : 0x%X (%d)' % (len(data), len(data)))
    print('+0x08  : %d frames = %.1f min' % (play, play / 60.0 / 60.0))
    print('props  : %s' % ctx)

    if restore:
        if not os.path.isfile(bakp):
            print('no backup at %s' % bakp)
            return 1
        # restore wholesale, not just the field, so the file is exactly as before
        shutil.copyfile(bakp, binp)
        print('RESTORED %s from %s' % (binp, os.path.basename(bakp)))
        now = struct.unpack_from('<I', open(binp, 'rb').read(), CHAPTER_OFF)[0]
        print('chapter now = %d' % now)
        return 0

    if len(pos) < 2 and playtime is None:
        print('current chapter = %d  "%s"' % (cur, NAMES.get(cur, '?')))
        print('usage: patch_chapter.py <slot> <chapter 0..%d> '
              '[--playtime frames]' % MAX_CHAPTER)
        return 2

    new = cur if len(pos) < 2 else int(pos[1], 0)
    if not 0 <= new <= MAX_CHAPTER:
        print('chapter %d out of range 0..%d' % (new, MAX_CHAPTER))
        return 1

    if not os.path.isfile(bakp):
        shutil.copyfile(binp, bakp)
        print('backup  : %s' % bakp)
    else:
        print('backup  : already present, leaving it alone (%s)' % bakp)

    before = bytearray(open(binp, 'rb').read())
    struct.pack_into('<I', data, CHAPTER_OFF, new)
    if playtime is not None:
        # marker: the game continues its play timer FROM whatever the slot
        # holds, so after a load+save the written value proves which file the
        # game actually read (original ~212896 vs marker 0x12345).
        struct.pack_into('<I', data, 0x08, playtime & 0xFFFFFFFF)
        print('marker : playtime set to 0x%X (%d frames)'
              % (playtime & 0xFFFFFFFF, playtime & 0xFFFFFFFF))
    changed = [i for i in range(len(data)) if before[i] != data[i]]
    if changed:
        print('bytes changed: %s' % ', '.join('0x%X' % c for c in changed))
    open(binp, 'wb').write(bytes(data))

    after = struct.unpack_from('<I', bytes(data), CHAPTER_OFF)[0]
    print('chapter %d -> %d   slot will read "Ch. %d, %s"'
          % (cur, after, after, NAMES.get(after, '?')))
    print('restore with: python patch_chapter.py %s --restore' % slot)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
