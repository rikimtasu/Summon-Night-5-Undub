# -*- coding: utf-8 -*-
"""Find the import stubs by finding jal targets that are not real functions.

Established so far:
  * the ELF rebases link-time vaddr (0x001xxxxx) to 0x08804000+; the fixup
    table [2] is standard MIPS: type 4 = R_MIPS_26 on jal targets, 5 = HI16,
    6 = LO16. sym=0, so the addend lives IN the instruction field - meaning
    every jal's in-file target is already the true link-time address.
  * .symtab is stripped (1 entry), so names are unavailable.
  * there are ~174 import NIDs packed at fva 0x211C94..0x211FBC (section 39).

Consequence: a call to an imported function must jal to a STUB, and a stub is
not a real function - it has no addiu-sp prologue and is only a couple of
instructions. So:

    for every jal in .text, take the target
    classify: does the target begin a function (prologue with negative addiu
              sp) or is it a tiny non-function?
    tally distinct non-function targets.

If imports work the way expected we should see on the order of 174 of them
(one per NID), clustered in one region. Those targets are the stub addresses,
and stub addresses are exactly what we need: enumerating their callers by
byte-searching for jal encodings gives real call edges with no string
addressing assumptions left.
"""
import struct
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x21121C]          # section 1 = code+rodata up to 0x21121C
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

insns = list(md.disasm(code, 0))
addr_idx = {i.address: n for n, i in enumerate(insns)}

# ---- function boundaries: prologue = addiu $sp,$sp,negative -------------
prologues = set()
for i in insns:
    if i.mnemonic == 'addiu' and i.op_str.startswith('$sp, $sp, -'):
        prologues.add(i.address)


def is_function(target):
    if target in prologues:
        return True
    # tolerate a compiler-saved-gateway: allow up to 2 insns before prologue
    n = addr_idx.get(target)
    if n is None:
        return None                     # target not on an instruction boundary
    for k in range(n, min(n + 3, len(insns))):
        if insns[k].address in prologues:
            return True
        if insns[k].mnemonic in ('jr', 'j', 'b'):
            break
    return False


jals = [i for i in insns if i.mnemonic == 'jal']
print('total jal instructions: %d' % len(jals))

targets = Counter()
unknown = 0
for i in jals:
    t = int(i.op_str, 0)
    targets[t] += 1

nonfunc = {}
func = 0
bad = 0
for t, c in targets.items():
    r = is_function(t)
    if r is True:
        func += 1
    elif r is False:
        nonfunc[t] = c
    else:
        bad += 1

print('distinct jal targets: %d' % len(targets))
print('  begin a function  : %d' % func)
print('  NOT a function    : %d   <-- import stub candidates' % len(nonfunc))
print('  off-boundary/unknown: %d' % bad)

print('\n=== non-function jal targets, by address ===')
for t in sorted(nonfunc):
    # show the bytes/insns at the target so the stub shape is visible
    n = addr_idx.get(t)
    body = ''
    if n is not None:
        seq = insns[n:n + 4]
        body = ' | '.join('%s %s' % (x.mnemonic, x.op_str) for x in seq[:3])
    print('  tgt 0x%06X  called %2d x   %s' % (t, nonfunc[t], body[:110]))

# cluster to find the stub region
if nonfunc:
    addrs = sorted(nonfunc)
    print('\n=== address span ===')
    print('  min 0x%06X  max 0x%06X  span 0x%X'
          % (addrs[0], addrs[-1], addrs[-1] - addrs[0]))
    gaps = [(addrs[i + 1] - addrs[i], addrs[i], addrs[i + 1])
            for i in range(len(addrs) - 1)]
    gaps.sort(reverse=True)
    print('  largest gaps:')
    for g, a, b in gaps[:5]:
        print('    0x%X between 0x%06X and 0x%06X' % (g, a, b))
print('DONE')
