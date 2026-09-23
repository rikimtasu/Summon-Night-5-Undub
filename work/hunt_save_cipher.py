# -*- coding: utf-8 -*-
"""Hunt the save cipher by its constants, not by the save code's data flow.

We know:
  - DATA.BIN is 170144 B, uniformly distributed, no repeated 8/16/32-byte
    blocks, no periodicity, and the XOR of any two saves is still
    high-entropy => per-save keystream, NOT ECB, not a fixed repeating key.
  - sceUtilitySavedata* is used, so PSP's own savedata API handles the file
    I/O; the cipher is the GAME's, in SaveLoad.cpp.

So look for the transformation itself. Rather than walk a 2 KB function, scan
for the fingerprints of the ciphers Japanese games actually ship:

  TEA / XTEA   : sum constant 0x9E3779B9, delta 0x61C88647
  XTEA variants : 0xC6EF3720, 0x9E3779B1
  MurmurHash fmix : 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F
  LCG constants : 0x41C64E6D, 0x3039, 0x6C078965 (Numerical Recipes),
                  0x5D588B65, 0x19660D, 0x5D588B65 (MSVC rand)
  xorshift      : 0x9D2C5680, 0x9E3779B9, 0x6C078965
  MWC           : 0xB5AD4ECEDA1CE2A9, 0xFFFF
  CRC32 table   : 0xEDB88320
  Blowfish/P-256: 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344
  Serpent/others: 0x9E3779B9 family
  Mersenne      : 0x9908B0DF, 0x6C078965

Also: scan .rodata for a 256/1024-entry u32 table (a CRC or AES S-box) and
report its fva - a 1024-word table of "random-looking" constants is a strong
tell for a cipher, and gives us something to xref.
"""
import struct
import math

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()

CONSTS = {
    0x9E3779B9: 'TEA delta / golden ratio',
    0x61C88647: 'TEA delta (signed)',
    0xC6EF3720: 'XTEA / oo)',
    0x9E3779B1: 'variant golden ratio',
    0x85EBCA6B: 'murmur fmix',
    0xC2B2AE35: 'murmur fmix 2',
    0x27D4EB2F: 'murmur fmix 3',
    0x41C64E6D: 'LCG (NR)',
    0x6C078965: 'LCG / xorshift (NR, MSVC-ish)',
    0x5D588B65: 'LCG (MSVC rand)',
    0x19660D: 'LCG (newer)',
    0xEDB88320: 'CRC32 polynomial',
    0x243F6A88: 'Blowfish / pi frac',
    0x85A308D3: 'pi frac 2',
    0x13198A2E: 'pi frac 3',
    0x03707344: 'pi frac 4',
    0x9908B0DF: 'MT19937',
    0x6A09E667: 'SHA-256 K[0]',
    0xBB67AE85: 'SHA-256 K[1]',
    0x67452301: 'MD5/SHA init A',
    0xEFCDAB89: 'MD5/SHA init B',
    0xD16AA24D: 'LCG low',
    0x2C1B3C6D: 'LCG low 2',
    0x7FEB352D: 'lowbias32',
    0x846CA68B: 'lowbias32 b',
    0x9E3779B7: 'mix32 const',
    0xDEADBEEF: 'debug marker',
    0x5A827999: 'SHA-1 K0',
    0x6ED9EBA1: 'SHA-1 K1',
    0x8F1BBCDC: 'SHA-1 K2',
    0xCA62C1D6: 'SHA-1 K3',
    0xA24BAED4: '3DES/other',
    0xB5AD4ECD: 'MWC mult (low word)',
    0x0000FFFF: 'mask16',
    0x9831: 'seed default (known)',
}

print('=== cipher constants present in the EBOOT ===')
found_any = False
for c, name in sorted(CONSTS.items(), key=lambda x: x[0]):
    b = struct.pack('<I', c)
    hits = []
    s = 0
    while True:
        i = d.find(b, s)
        if i < 0:
            break
        hits.append(i)
        s = i + 1
    if hits:
        found_any = True
        shown = [hex(x) for x in hits[:8]]
        print('  0x%08X  %-28s %d hit(s) %s' % (c, name, len(hits), shown))
if not found_any:
    print('  none of the common cipher constants appear')

# scan for a u32 table that looks like cipher material
print('\n=== scanning .rodata for large random-looking u32 tables ===')
# .rodata is roughly file 0x210000..0x242C94 (after SEG)
RO_LO, RO_HI = 0x210000, 0x242C00
words = []
for o in range(RO_LO, RO_HI - 4, 4):
    w = struct.unpack_from('<I', d, o)[0]
    words.append((o, w))

# measure entropy of consecutive 256-word windows
import collections
best = []
W = 256
for i in range(0, len(words) - W):
    win = [w for _, w in words[i:i + W]]
    c = collections.Counter(win)
    n = len(win)
    ent = -sum((v / n) * math.log2(v / n) for v in c.values())
    # "random-looking": high entropy AND few small/repeated values
    small = sum(1 for w in win if w < 0x10000)
    best.append((ent, -small, words[i][0], words[i + W - 1][0]))
best.sort(reverse=True)
print('  top windows by u32 entropy (candidates: CRC/S-box/key schedule):')
seen = []
for ent, negsmall, a, b in best[:400]:
    if any(abs(a - s) < 0x2000 for s in seen):
        continue
    seen.append(a)
    hi = -negsmall
    print('    fva 0x%06X..0x%06X  ent=%.2f bits  words<64K=%d/%d' % (a, b, ent, hi, W))
    if len(seen) >= 8:
        break
print('DONE')
