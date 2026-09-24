# -*- coding: utf-8 -*-
"""Are the saves written with PPSSPP EncryptSave=False actually plaintext?

This resolves the contradiction that has dominated the whole investigation:

  * DATA.BIN measures as encrypted - entropy 7.9988-7.9992 over 170144 bytes
    (the uniform-random ceiling for that sample size), chi2 z within +/-2.4,
    two saves of the same player differing at 99.6% from byte 0 with no
    shared 16-byte block, no valid deflate/gzip/lzma stream anywhere
  * yet the EBOOT's entire save path - SaveLoadGame 0x1461B4,
    SaveLoadSystem 0x146604, SaveLoadSuspend 0x146844, their 7 shared
    callees, their 6 parents - contains 0/1/0 xor instructions and no
    loop that walks a 170 KB buffer (SaveLoadSuspend has no backward branch
    at all)

Both cannot be true if the game encrypts. The escape is that PPSSPP's own
EncryptSave option performs the wrapping, so the game code legitimately has
no cipher in it.

So take two saves produced with EncryptSave=False and measure them against
the encrypted baseline:

    ULUS10656SN5GAME45   US, new
    NPJH50696SN5GAME06   JP, new

Decrypted expectation: entropy far below 8 (a real struct has huge low-entropy
regions - name fields, counters, empty slots), chi2 z wildly non-zero, long
printable runs, and a stable header across both files.

Encrypted expectation: entropy ~7.999, chi2 z ~0, no strings - identical in
character to GAME46/47 and GAME00-05.

Also: the size fields written by SaveLoadGame are 0x29890 while the file is
0x298A0 - a 16-byte difference. If those are header+payload, the first 16
bytes deserve their own look.
"""
import os
import math
import collections

ROOT = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\SAVEDATA'
NEW = ['ULUS10656SN5GAME45', 'NPJH50696SN5GAME06']
OLD = ['ULUS10656SN5GAME46', 'ULUS10656SN5GAME47',
       'NPJH50696SN5GAME00', 'NPJH50696SN5GAME05',
       'ULUS10656SN5SYSTEM', 'NPJH50696SN5SYSTEM']


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


def hexdump(b, base=0, n=256):
    out = []
    for i in range(0, min(n, len(b)), 16):
        row = b[i:i + 16]
        out.append('%08X  %-47s  |%s|'
                   % (base + i,
                      ' '.join('%02X' % x for x in row),
                      ''.join(chr(x) if 0x20 <= x < 0x7e else '.' for x in row)))
    return '\n'.join(out)


def strings(b, lo=6):
    runs, cur, st = [], 0, 0
    for i, ch in enumerate(b):
        if 0x20 <= ch < 0x7f:
            if cur == 0:
                st = i
            cur += 1
        else:
            if cur >= lo:
                runs.append((st, b[st:st + cur].decode('latin-1')))
            cur = 0
    if cur >= lo:
        runs.append((st, b[st:st + cur].decode('latin-1')))
    return runs


def load(name):
    p = os.path.join(ROOT, name)
    if not os.path.isdir(p):
        return None, None
    files = sorted(os.listdir(p))
    dp = os.path.join(p, 'DATA.BIN')
    if not os.path.isfile(dp):
        return files, None
    return files, open(dp, 'rb').read()


print('=' * 78)
print('NEW SAVES (EncryptSave=False)')
print('=' * 78)
new = {}
for nm in NEW:
    files, data = load(nm)
    print('\n### %s' % nm)
    if files is None:
        print('  DIRECTORY DOES NOT EXIST')
        continue
    print('  dir contents: %s' % ', '.join(
        '%s(%d)' % (f, os.path.getsize(os.path.join(ROOT, nm, f)))
        for f in files))
    if data is None:
        print('  no DATA.BIN')
        continue
    new[nm] = data
    print('  size=%d (0x%X)  entropy=%.5f  chi2z=%+.2f'
          % (len(data), len(data), entropy(data), chi2z(data)))
    print('  first 16 bytes: %s' % ' '.join('%02X' % x for x in data[:16]))
    print('  bytes 16..32  : %s' % ' '.join('%02X' % x for x in data[16:32]))
    st = strings(data)
    print('  printable runs >=6: %d ; longest=%d'
          % (len(st), max((len(s) for _, s in st), default=0)))
    for off, s in st[:10]:
        print('      0x%-6X %r' % (off, s[:70]))
    print('  --- hexdump first 256 ---')
    print(hexdump(data, 0, 256))

print('\n' + '=' * 78)
print('ENCRYPTED BASELINE (for comparison)')
print('=' * 78)
old = {}
for nm in OLD:
    files, data = load(nm)
    if data is None:
        print('  %-24s missing/no DATA.BIN' % nm)
        continue
    old[nm] = data
    st = strings(data)
    print('  %-24s size=%-7d entropy=%.5f chi2z=%+.2f strings>=6: %d'
          % (nm, len(data), entropy(data), chi2z(data), len(st)))

# ---- verdict ------------------------------------------------------------
print('\n' + '=' * 78)
print('VERDICT')
print('=' * 78)
for nm, data in new.items():
    e = entropy(data)
    z = chi2z(data)
    ns = len(strings(data))
    encrypted = e > 7.99 and abs(z) < 4 and ns < 20
    print('  %-24s entropy=%.5f chi2z=%+.2f strings=%-4d -> %s'
          % (nm, e, z, ns,
             'STILL ENCRYPTED' if encrypted else 'PLAINTEXT / DECRYPTED'))

# ---- if plaintext, look for structure ----------------------------------
for nm, data in new.items():
    if entropy(data) > 7.9 and len(strings(data)) < 20:
        continue
    print('\n--- structure probe: %s ---' % nm)
    # 4-byte words: how many are small integers / pointers?
    small = zero = ptr = 0
    for i in range(0, len(data) - 3, 4):
        w = (data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24)
        if w == 0:
            zero += 1
        elif w < 0x10000:
            small += 1
        elif 0x08800000 <= w < 0x0A000000:
            ptr += 1
    nwords = len(data) // 4
    print('  words=%d  zero=%d (%.1f%%)  small(<0x10000)=%d (%.1f%%)  '
          'psp-ptr=%d' % (nwords, zero, 100.0 * zero / nwords,
                          small, 100.0 * small / nwords, ptr))
    # byte histogram of first 4096 vs rest
    print('  entropy head4k=%.4f  rest=%.4f'
          % (entropy(data[:4096]), entropy(data[4096:])))
    # is there a 16-byte header?
    print('  header[0:16]=%s' % ' '.join('%02X' % x for x in data[:16]))
    print('  entropy(data[16:])=%.5f  chi2z=%+.2f'
          % (entropy(data[16:]), chi2z(data[16:])))
print('DONE')
