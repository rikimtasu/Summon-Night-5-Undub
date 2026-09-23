# -*- coding: utf-8 -*-
"""Find the save cipher by fingerprinting byte/word-wise XOR loops.

Reasoning so far:
  - on-disk DATA.BIN is uniformly random, 170144 B fixed, per-save keystream,
    no ECB block repetition, no periodicity
  - the raw buffer is NOT resident in mid-game save states, so the plaintext
    cannot be lifted from RAM without a state captured on the load/save screen
  - the EBOOT has a standard zlib CRC-32 table at fva 0x21FF00 (256 u32;
    entry[64] = 0xEDB88320 is the polynomial, which is what matched), i.e. the
    game checksums saves - but CRC is not a cipher

Custom save ciphers in this era are almost always one of:
  (a) word-wise XOR with a PRNG keystream  -> lwl/lwr (load) + xor + swl/swr
  (b) byte-wise XOR in a loop             -> lbu + xor + sb
  (c) a small block cipher in a loop      -> lwl/lwr + shifts + swl/swr

lwl/lwr/swl/swr (the unaligned load/store word ops) are the strongest tell: a
plain-textbook byte loop uses lbu/sb, but any cipher fast enough to run over
170 KB uses the unaligned word ops. So: find every function containing a
cluster of those ops, and rank by cluster size. Then show the top candidates
with their call counts.
"""
import struct
from collections import defaultdict
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

WORDOPS = {'lwl', 'lwr', 'swl', 'swr'}
XOROPS = {'xor', 'xori'}

insns = list(md.disasm(code, 0))
addr2idx = {i.address: n for n, i in enumerate(insns)}

# function boundaries: a prologue (addiu sp,sp,-N) preceded by a jr ra / nop
funcs = []
for n, ins in enumerate(insns):
    if ins.mnemonic == 'addiu' and ins.op_str.startswith('$sp, $sp, -'):
        funcs.append(ins.address)
funcs.append(len(code))
print('prologue candidates: %d' % (len(funcs) - 1))

# assign each instruction to the function containing it
bounds = funcs


def fn_of(a):
    lo, hi = 0, len(bounds) - 2
    while lo <= hi:
        mid = (lo + hi) // 2
        if bounds[mid] <= a:
            lo = mid + 1
        else:
            hi = mid - 1
    return bounds[max(0, lo - 1)]


# cluster word-ops per function
wordcnt = defaultdict(int)
xorcnt = defaultdict(int)
total = defaultdict(int)
for ins in insns:
    f = fn_of(ins.address)
    total[f] += 1
    if ins.mnemonic in WORDOPS:
        wordcnt[f] += 1
    if ins.mnemonic in XOROPS:
        xorcnt[f] += 1


def callers(t):
    enc = struct.pack('<I', 0x0C000000 | (t >> 2))
    out = []
    s = 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


cands = []
for f in wordcnt:
    if wordcnt[f] >= 6 and xorcnt[f] >= 2:
        cands.append((wordcnt[f] + xorcnt[f], f, wordcnt[f], xorcnt[f], total[f]))
cands.sort(reverse=True)
print('\n=== functions with dense word-op + xor clusters (cipher candidates) ===')
for score, f, wc, xc, tc in cands[:20]:
    print('  fn 0x%06X  wordops=%-4d xors=%-4d size=%-5d score=%-4d callers=%d'
          % (f, wc, xc, tc, score, len(callers(f))))

print('\n=== xrefs to the CRC-32 table base 0x21FF00 ===')
ins_list = insns
lui_at = {}
for n, ins in enumerate(ins_list):
    if ins.mnemonic == 'lui':
        r, v = [x.strip() for x in ins.op_str.split(',')]
        lui_at[r] = (n, int(v, 0))
    elif ins.mnemonic in ('ori', 'addiu'):
        p = [x.strip() for x in ins.op_str.split(',')]
        if len(p) != 3 or p[1] not in lui_at:
            continue
        li, hi = lui_at[p[1]]
        if n - li > 8:
            continue
        imm = int(p[2], 0)
        if imm & 0x8000:
            imm -= 0x10000
        full = ((hi << 16) + imm) & 0xFFFFFFFF
        if full in (0x21FF00, 0x220100):
            print('  0x%06X -> 0x%06X  in fn 0x%06X  callers=%d'
                  % (ins.address, full, fn_of(ins.address),
                     len(callers(fn_of(ins.address)))))
print('DONE')
