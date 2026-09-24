# -*- coding: utf-8 -*-
"""Close the two remaining gaps in the save-cipher hunt.

Established: DATA.BIN is encrypted (entropy 7.9988-7.9992 over 170144 bytes =
the uniform-random maximum for that sample size; chi2 z within +/-2.4; two JP
saves differ at 99.62% from byte 0). Yet SaveLoadGame/SaveLoadSystem/
SaveLoadSuspend, their 7 shared callees, and their 6 parents all contain no
xor. Two holes in that negative result:

(1) SIZE CONSTANTS. find_size_consts.py looked for 0x298A0 (170144) as a raw
    u32 or a lui/ori pair. But `lui 3 ; addiu -0x6760` also forms 0x298A0, and
    that is the exact negative-immediate form the sign bug destroyed
    everywhere else. Re-search with the corrected arithmetic, over both ori and
    addiu, for 0x298A0, 0x58E0 (22752 = SYSTEM size), and 0xA000.

(2) INDIRECT DISPATCH. Every call-graph walk so far classified only `jal`.
    This binary has 4318 `jalr $t9` fed by `lw $t9, off(base)` - a struct-
    embedded function-pointer dispatch (samples were `lw $t9, 4($a0)`). If the
    cipher is invoked through a stored function pointer, no jal-based walk will
    ever reach it. So enumerate every jalr inside the save cluster and its
    callees and print the surrounding instructions.

(3) Bonus: re-xref the CRC-32 table at 0x21FF00 over a RANGE (0x21FE00..
    0x220400) rather than the exact base, because `table[i]` is materialised as
    `lui/addiu` to base+const then a small final displacement - an exact-match
    search structurally cannot see it. If the save has a checksum we must
    recompute it after editing, so this matters for the end goal.
"""
import array
import struct
import bisect
from collections import defaultdict
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

words = array.array('I')
words.frombytes(code[:len(code) // 4 * 4])
PRO = sorted(i * 4 for i, x in enumerate(words)
             if (x >> 16) == 0x27BD and (x & 0x8000))


def extent(a):
    i = bisect.bisect_right(PRO, a + 8)
    return PRO[i] if i < len(PRO) else len(code)


def callers(t):
    enc = struct.pack('<I', 0x0C000000 | (t >> 2))
    out, s = [], 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


def imm_of(tok, mn):
    """Correct immediate: capstone prints addiu already signed."""
    t = tok.strip()
    if mn == 'ori':
        return int(t, 0) & 0xFFFF
    v = int(t, 0)
    if t.startswith('-') or v < 0:
        return v
    return v - 0x10000 if v >= 0x8000 else v


insns = list(md.disasm(code, 0))
lui_at = {}
resolved = []          # (addr, mn, value)
for n, ins in enumerate(insns):
    ops = [x.strip() for x in ins.op_str.split(',')]
    if ins.mnemonic == 'lui' and len(ops) == 2:
        lui_at[ops[0]] = (n, int(ops[1], 0))
    elif ins.mnemonic in ('ori', 'addiu') and len(ops) == 3 and ops[1] in lui_at:
        li, hi = lui_at[ops[1]]
        if n - li > 16:
            continue
        v = ((hi << 16) + imm_of(ops[2], ins.mnemonic)) & 0xFFFFFFFF
        resolved.append((ins.address, ins.mnemonic, v))

by_val = defaultdict(list)
for a, mn, v in resolved:
    by_val[v].append((a, mn))

print('=== (1) size constants, CORRECTED arithmetic ===')
for want in (0x298A0, 0x58E0, 0xA000, 0x7E4, 0x17E4, 0x29890):
    hits = by_val.get(want, [])
    print('  0x%-7X -> %d site(s)' % (want, len(hits)))
    for a, mn in hits[:8]:
        st = None
        for p in reversed(PRO):
            if p <= a:
                st = p
                break
        print('        0x%06X %-6s [fn 0x%06X callers=%d]'
              % (a, mn, st, len(callers(st))))

print('\n=== (3) CRC-32 table range xref 0x21FE00..0x220400 ===')
found = False
for a, mn, v in resolved:
    if 0x21FE00 <= v < 0x220400:
        found = True
        st = None
        for p in reversed(PRO):
            if p <= a:
                st = p
                break
        print('  0x%06X %-6s -> 0x%06X [fn 0x%06X callers=%d]'
              % (a, mn, v, st, len(callers(st))))
if not found:
    print('  none - no lui/addiu-derived address lands in the CRC table range')

# ---- (2) jalr inside the save cluster and its callees -------------------
print('\n=== (2) indirect calls (jalr) reachable from the save subsystem ===')
SAVE = [0x1461B4, 0x146604, 0x146844, 0x142B4C, 0x142CDC, 0x142DF0,
        0x143050, 0x143184, 0x145C04, 0x132C8C, 0x1414D4,
        0x14369C, 0x1439C8, 0x143B54, 0x1470B0, 0x143734,
        0x142910, 0x1434A4, 0x14441C, 0x141610, 0x141690]

seen = set()
stack = list(SAVE)
depth = {}
for s in SAVE:
    depth[s] = 0
while stack:
    fn = stack.pop()
    if fn in seen:
        continue
    seen.add(fn)
    ins = list(md.disasm(code[fn:extent(fn)], fn))
    for i in ins:
        if i.mnemonic == 'jal':
            t = int(i.op_str, 0)
            if t not in seen and depth.get(fn, 0) < 3:
                depth[t] = depth.get(fn, 0) + 1
                stack.append(t)

jalr_sites = []
for fn in sorted(seen):
    for i in md.disasm(code[fn:extent(fn)], fn):
        if i.mnemonic == 'jalr':
            jalr_sites.append((fn, i.address))
print('  functions walked: %d   jalr sites found: %d'
      % (len(seen), len(jalr_sites)))
for fn, a in jalr_sites[:40]:
    print('  jalr in fn 0x%06X at 0x%06X:' % (fn, a))
    # print the 6 instructions before and the jalr, to show how target formed
    for j in md.disasm(code[max(0, a - 24):a + 4], a - 24):
        print('      0x%X: %-8s %s' % (j.address, j.mnemonic, j.op_str))
if len(jalr_sites) > 40:
    print('  ... %d more' % (len(jalr_sites) - 40))
print('DONE')
