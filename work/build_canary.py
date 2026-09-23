"""Canary build: find loader-clean zero gaps that survive to runtime.

Writes unique 16B canaries into ~15 spread gaps (including one control inside
the failed v3 cave neighborhood). User boots to TITLE and saves state; readback
tells which placements survive (load + boot stable). Then the real cave+table
goes in the biggest surviving gap.
"""
import struct
import pickle
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_undub_v2 as v2

SRC_PATCHED = v2.PATCHED_EBOOT  # current v3r2 patched file (keep NOPs+hook+cave)
SEG = 0xC0
CANARY_MAGIC = 0xC0FFEE11


def pick_gaps(d, diff, nbins=14):
    n = 0x242C94
    runs = []
    i = 0
    while i < n:
        if i not in diff and d[SEG + i] == 0:
            j = i
            while j < n and j not in diff and d[SEG + j] == 0:
                j += 1
            if j - i >= 24:
                runs.append((i, j - i))
            i = j
        else:
            i += 1
    # largest run per address bin
    picks = []
    for b in range(nbins):
        lo, hi = b * n // nbins, (b + 1) * n // nbins
        cands = [(a, l) for (a, l) in runs if lo <= a < hi]
        if cands:
            picks.append(max(cands, key=lambda x: x[1]))
    return picks


def main():
    d = bytearray(open(SRC_PATCHED, 'rb').read())
    diff = pickle.loads(open(r'D:\Documents\Default Project\work\usa_loader_diff.pkl', 'rb').read())
    picks = pick_gaps(d, diff)
    print('bin picks:', [(hex(a), l) for a, l in picks])
    # control inside failed neighborhood (big zero gap, outside v3 cave)
    control = 0x236378 + 8000
    assert all(b == 0 for b in d[SEG + control:SEG + control + 16])
    assert not any(c in diff for c in range(control, control + 16, 4))
    spots = [(a + ((-a) % 4), idx) for idx, (a, l) in enumerate(picks)]
    spots.append((control, 99))
    table = []
    for addr, idx in spots:
        blob = struct.pack('<4I', CANARY_MAGIC, idx, addr, (~idx) & 0xFFFFFFFF)
        assert all(b == 0 for b in d[SEG + addr:SEG + addr + 16]), hex(addr)
        d[SEG + addr:SEG + addr + 16] = blob
        table.append((idx, addr))
        print(f'canary {idx} at fva {addr:#x} (rt {addr + 0x08804000:#x})')
    with open(SRC_PATCHED, 'wb') as f:
        f.write(d)
    with open(r'D:\Documents\Default Project\work\canaries.txt', 'w') as f:
        for idx, addr in table:
            f.write(f'{idx} {addr:#x} {addr + 0x08804000:#x}\n')
    print('canary EBOOT written; now run extent overwrite')
    v2.patch_eboot_extent()
    print('done:', v2.OUT_ISO)


if __name__ == '__main__':
    main()
