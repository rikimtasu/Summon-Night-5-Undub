# -*- coding: utf-8 -*-
"""Decide compression vs encryption on the real SN5 DATA.BIN files.

Facts so far:
  * the EBOOT's save path (SaveLoadGame 0x1461B4, SaveLoadSystem 0x146604,
    SaveLoadSuspend 0x146844) contains 0 / 1 / 0 XOR instructions
  * their seven shared callees are the savedata state machine, two constant
    accessors, strncpy, a wrapper and printf - no transform
  * SaveLoadSuspend has no backward branch at all, so it cannot loop over the
    buffer
  * yet two JP saves differ at 169496/170144 bytes starting at byte 0, and
    share no 16-byte block

"Very different, high entropy, no XOR" is explained equally well by
COMPRESSION as by encryption - and deflate/ise expansion uses table lookups
and copies, not xor. Compression would also mean the saves are directly
editable, which changes the whole project.

So: try to inflate. Scan for every real stream header (zlib 78 xx, gzip
1F 8B, lzma 5D 00, bzip2 42 5A 68) AND brute-force raw-deflate (wbits -9..-15)
over the first 512 offsets. A successful inflate gives plaintext directly.

Also compare compression-expected statistics against encryption-expected:
deflate output is high entropy but measurably below 8.00 and its byte
histogram is non-uniform in a characteristic way, while a keystream is
flat. Report entropy to 5 dp plus chi-square z over the whole file, and
show where identical bytes sit between the two US saves - a plaintext struct
would put them at fixed field offsets, encryption scatters them.
"""
import os
import zlib
import math
import collections

ROOT = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = float(len(b))
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def chi2z(b):
    if len(b) < 4096:
        return 0.0
    c = collections.Counter(b)
    exp = len(b) / 256.0
    chi = sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))
    return (chi - 255.0) / math.sqrt(2.0 * 255.0)


def try_inflate(data):
    """Try every plausible decompressor at every plausible offset.
    Returns list of (where, how, outlen, outent)."""
    hits = []
    # explicit magic headers across the whole file
    magics = [(b'\x78\x9c', 15, 'zlib'), (b'\x78\xda', 15, 'zlib'),
              (b'\x78\x01', 15, 'zlib'), (b'\x78\x5e', 15, 'zlib'),
              (b'\x1f\x8b\x08', 31, 'gzip')]
    for mag, wb, nm in magics:
        s = 0
        while True:
            i = data.find(mag, s)
            if i < 0 or i > 65536:
                break
            try:
                out = zlib.decompress(data[i:], wb)
                hits.append(('%s@0x%X' % (nm, i), wb, len(out),
                             entropy(out[:65536])))
            except Exception:
                pass
            s = i + 1
    # brute-force raw deflate over the head of the file
    for i in range(min(512, len(data))):
        for wb in (-9, -10, -11, -12, -13, -14, -15):
            try:
                out = zlib.decompress(data[i:], wb)
            except Exception:
                continue
            if len(out) >= 64:
                hits.append(('rawdeflate wbits=%d @0x%X' % (wb, i), wb,
                             len(out), entropy(out[:65536])))
    return hits


print('=== SN5 save directories ===')
dirs = sorted(d for d in os.listdir(ROOT) if 'SN5' in d.upper())
saves = {}
for dd in dirs:
    p = os.path.join(ROOT, dd, 'DATA.BIN')
    if not os.path.isfile(p):
        print('  %-24s (no DATA.BIN)' % dd)
        continue
    data = open(p, 'rb').read()
    saves[dd] = data
    print('  %-24s size=%-7d ent=%.5f chi2z=%+.2f  head=%s'
          % (dd, len(data), entropy(data), chi2z(data),
             ' '.join('%02X' % b for b in data[:24])))

print('\n=== decompression attempts ===')
any_hit = False
for dd in sorted(saves):
    hits = try_inflate(saves[dd])
    if hits:
        any_hit = True
        print('  %s -> %d SUCCESS' % (dd, len(hits)))
        for h in hits[:6]:
            print('      %s  outlen=%d outent=%.4f' % (h[0], h[2], h[3]))
    else:
        print('  %s -> no valid stream in head (512 off x 7 wbits, magics)'
              % dd)
if not any_hit:
    print('\n  => NOT zlib/gzip/deflate-compressed (at least not at the head)')

# ---- identical-byte structure between the two US saves ------------------
us = [k for k in saves if k.startswith('ULUS10656SN5GAME')]
if len(us) >= 2:
    a, b = saves[us[0]], saves[us[1]]
    m = min(len(a), len(b))
    same = [i for i in range(m) if a[i] == b[i]]
    print('\n=== %s vs %s ===' % (us[0], us[1]))
    print('  compared %d, identical %d (%.3f%%)'
          % (m, len(same), 100.0 * len(same) / m))
    print('  first 40 identical offsets: %s'
          % ', '.join('0x%X' % i for i in same[:40]))
    # are they clustered (structure) or scattered (random)?
    if same:
        gaps = [same[i + 1] - same[i] for i in range(len(same) - 1)]
        print('  identical-byte gap mean=%.1f max=%d'
              % (sum(gaps) / float(len(gaps)) if gaps else 0,
                 max(gaps) if gaps else 0))
        # contiguity: longest run of consecutive identical offsets
        best = run = 1
        for i in range(len(same) - 1):
            run = run + 1 if same[i + 1] == same[i] + 1 else 1
            best = max(best, run)
        print('  longest consecutive identical run = %d bytes' % best)

# ---- does DATA.BIN hold readable text at all? ---------------------------
print('\n=== printable-ASCII content (longest run, and all runs >= 8) ===')
for dd in sorted(saves):
    data = saves[dd]
    runs, cur = [], 0
    for i, ch in enumerate(data):
        if 0x20 <= ch < 0x7f:
            cur += 1
        else:
            if cur >= 8:
                runs.append((i - cur, cur))
            cur = 0
    top = max((r[1] for r in runs), default=0)
    print('  %-24s longest_ascii_run=%-4d runs>=8: %d  e.g. %s'
          % (dd, top, len(runs),
             ', '.join('0x%X:%d' % r for r in runs[:4]) or '-'))
print('DONE')
