"""Loader-probe build: fill [0x236000, 0x238400) with address-echo pattern.

Title-state readback reveals EXACTLY which words the loader touches
(zero-writers are invisible to file-vs-RAM diffing, which is why the cave
died). Survivors map the safe home for the real cave+table.
Pattern word = 0x90000000 | (fva & 0x00FFFFFF) -- always nonzero, echoes addr.
"""
import struct
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_undub_v2 as v2

SRC_PATCHED = v2.PATCHED_EBOOT  # current file (v3r2 + 14 canaries)
SEG = 0xC0
FILL_LO, FILL_HI = 0x236000, 0x238400


def main():
    d = bytearray(open(SRC_PATCHED, 'rb').read())
    n = 0
    for fva in range(FILL_LO, FILL_HI, 4):
        d[SEG + fva:SEG + fva + 4] = struct.pack('<I', 0x90000000 | (fva & 0x00FFFFFF))
        n += 1
    with open(SRC_PATCHED, 'wb') as f:
        f.write(d)
    print(f'pattern-filled {n} words in [{FILL_LO:#x}, {FILL_HI:#x})')
    v2.patch_eboot_extent()
    print('done:', v2.OUT_ISO)


if __name__ == '__main__':
    main()
