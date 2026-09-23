"""Probe-2: pattern-fill candidate chunk homes + upper-range scan.

Fill (magic 0xA0+fva-echo):
 - top gaps < 0x236000 (avoid Z1 game-buffer + Z2 dead zone): ~5.4KB total
 - upper range [0x238400, 0x23E400): find Z2's upper edge / backup space
Title readback: fully-intact gaps = placement map for split code+table.
"""
import struct
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_undub_v2 as v2

SRC_PATCHED = v2.PATCHED_EBOOT
SEG = 0xC0
MAGIC = 0xA0000000
# (start, len) -- loader-clean zero gaps (from size-ranked scan), 4-aligned
GAPS = [
    (0x224868, 664), (0x2334F4, 648), (0x22E33C, 496), (0x2242B8, 396),
    (0x22FEC0, 380), (0x2240E4, 380), (0x223C40, 332), (0x22B760, 332),
    (0x22D164, 332), (0x223E30, 304), (0x224F20, 288), (0x22F2F0, 280),
    (0x224B28, 280), (0x22FAFE, 256),
]
UPPER = (0x238400, 0x23E400)


def main():
    d = bytearray(open(SRC_PATCHED, 'rb').read())
    total = 0
    regions = [(a, l) for (a, l) in GAPS] + [(UPPER[0], UPPER[1] - UPPER[0])]
    with open(r'D:\Documents\Default Project\work\probe2_regions.txt', 'w') as f:
        for (a, ln) in regions:
            assert ln % 4 == 0, hex(a)
            for fva in range(a, a + ln, 4):
                d[SEG + fva:SEG + fva + 4] = struct.pack('<I', MAGIC | (fva & 0x00FFFFFF))
                total += 1
            f.write(f'{a:#x} {ln}\n')
    with open(SRC_PATCHED, 'wb') as f:
        f.write(d)
    print(f'pattern-filled {total} words in {len(regions)} regions')
    v2.patch_eboot_extent()
    print('done:', v2.OUT_ISO)


if __name__ == '__main__':
    main()
