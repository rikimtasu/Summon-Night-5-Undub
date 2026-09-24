# -*- coding: utf-8 -*-
"""Crib search: is the story token stream stored raw inside the containers?

Facts so far:
  * 11.DAT (both versions) holds 136 blocks with the 0x10000201/0x10000002
    header pair, but all are small (c10 <= 1356, size <= 5376). The 150-250 KB
    chapter script that appears in RAM is NOT among them.
  * No container contains the header magic at a story-sized block, and no known
    dialogue appears verbatim (utf-8 / shift_jis / utf-16le) in 00/01/02/03/10.

Hypothesis under test: the big RAM block is ASSEMBLED at load time from many
smaller units, so its raw token bytes (or its string pool) appear somewhere in a
container WITHOUT the block header.  We own a crib - the prologue block read
from a RAM dump - so we can search every container for its first tokens, its
pool strings, or its byte histogram signature.

If a hit lands, the container format is cracked and every chapter can be
enumerated offline with no game boot at all.

Run:  python crib_search_story_tokens.py
"""
import glob
import os
import struct
import sys

WORK = r'D:\Documents\Default Project\work'
MAGIC_PAIR = struct.pack('<II', 0x10000201, 0x10000002)
CONTAINERS = []
for tag in ('JP', 'USA'):
    d = os.path.join(WORK, tag, 'PSP_GAME', 'USRDIR')
    if os.path.isdir(d):
        for p in sorted(glob.glob(os.path.join(d, '*.DAT'))):
            CONTAINERS.append((tag, p))


def find_story_block(ram):
    """First RAM block with a story-sized c10 (>= 20000)."""
    s = 0
    while True:
        o = ram.find(MAGIC_PAIR, s)
        if o < 0:
            return None
        s = o + 1
        size = struct.unpack_from('<I', ram, o + 8)[0]
        c10 = struct.unpack_from('<I', ram, o + 16)[0]
        if c10 >= 20000 and c10 * 2 <= size <= 0xC0000:
            return o, size, c10


def main():
    cribs = []
    for path in sorted(glob.glob(os.path.join(WORK, 'psp_ram_*.bin'))):
        ram = open(path, 'rb').read()
        hit = find_story_block(ram)
        if hit:
            o, size, c10 = hit
            blk = ram[o:o + size]
            cribs.append((os.path.basename(path), blk, c10, size))
        del ram
    if not cribs:
        print('no story block in any RAM dump - need a dump to crib from')
        return 1

    for name, blk, c10, size in cribs:
        print('crib from %s: c10=%d size=%d' % (name, c10, size))
        # token area starts at byte 24; pool starts at c10*2
        tok = blk[24:24 + 128]
        pool_at = c10 * 2
        pool = blk[pool_at:pool_at + 128]
        # a mid-stream token slice too, in case the head is special
        mid = blk[c10: c10 + 128]
        probes = [('tokens[0:128]', tok), ('pool[0:128]', pool),
                  ('tokens[mid:mid+128]', mid)]
        for tag, path in CONTAINERS:
            data = open(path, 'rb').read()
            for label, needle in probes:
                o = data.find(needle)
                if o >= 0:
                    print('  HIT %-22s %-24s at 0x%X' % (tag, label, o))
            del data
        print('  (no hits above = tokens/pool are not stored raw)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
