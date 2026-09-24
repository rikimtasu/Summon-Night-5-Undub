# -*- coding: utf-8 -*-
"""Resolve WHERE each jalr loads its target from - that locates the imports.

Previous result: 33,349 direct jal (ordinary calls) and 4,318 jalr, every one
of them fed by `lw $t9, off($reg)`. The binary has no DYNAMIC segment, only the
0x700000A0 reloc segment, so imported functions cannot be resolved by a dynamic
linker - they must be SLOTS that the loader patches, and the code reads those
slots with lw then jalr.

I was tracing the wrong register. The jalr's target register is trivially a lw;
what matters is the BASE register of that lw. Two very different shapes:

    lw $t9, 0($v0)   where $v0 came from the object  -> C++ virtual dispatch
                                                          (vtable / factory;
                                                          this binary clearly
                                                          has these: comSvSaveLoad
                                                          registers into 0x1AD500)
    lw $t9, OFF($r)  where $r = lui+addiu to a CONSTANT
                                          -> load from a fixed pointer table,
                                             i.e. possibly an import slot

So for each jalr: take the feeding lw, get its base register, walk backwards to
find how that base was formed, and classify. Collect every constant base
address reached this way. If a cluster lands next to the NID table (fva
0x211C94..0x211FBC, section 39) then those slots are the imports, and the slot
index gives the NID.
"""
import struct
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x21121C]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False
insns = list(md.disasm(code, 0))

# function starts, so backwards scans stop at a boundary
prologues = set()
for i in insns:
    if i.mnemonic == 'addiu' and i.op_str.startswith('$sp, $sp, -'):
        prologues.add(i.address)


def op_list(ins):
    return [x.strip() for x in ins.op_str.split(',')]


def resolve_base(n, reg, span=64):
    """Walk back from index n looking for how `reg` was formed."""
    hi = None
    for k in range(n - 1, max(-1, n - span), -1):
        ins = insns[k]
        ops = op_list(ins)
        if ins.address in prologues:
            break
        if ins.mnemonic == 'lui' and ops[0] == reg:
            hi = int(ops[1], 0)
            # paired ori/addiu on same reg, forward scan
            for m in range(k + 1, min(k + 8, n + 1)):
                o2 = insns[m]
                p2 = op_list(o2)
                if o2.mnemonic in ('ori', 'addiu') and len(p2) == 3 and p2[1] == reg:
                    imm = int(p2[2], 0)
                    if o2.mnemonic == 'addiu' and imm & 0x8000:
                        imm -= 0x10000
                    return ('const', ((hi << 16) + imm) & 0xFFFFFFFF, ins.address)
            return ('lui-only', hi, ins.address)
        # load of a vptr from an object, or lw from another register
        if ins.mnemonic == 'lw' and len(ops) == 2:
            base = ops[1]
            if base.endswith(')'):
                breg = base.split('(')[-1].rstrip(')')
                if breg in ('$sp', '$gp'):
                    return ('sp/gp-relative', None, ins.address)
                # could itself be an object pointer -> keep looking but note it
                continue
        if ins.mnemonic in ('move', 'addu', 'or', 'addiu', 'lw', 'lwl') and ops[0] == reg:
            # dependency on another reg; try to identify object-relative
            for o in ops[1:]:
                if o.startswith('$s') or o.startswith('$a') or o.startswith('$t'):
                    pass
            return ('reg-derived', None, ins.address)
    return ('unresolved', None, None)


kinds = Counter()
const_bases = Counter()
base_samples = defaultdict(list)
lw_sites = []

for n, ins in enumerate(insns):
    if ins.mnemonic != 'jalr':
        continue
    # find the feeding lw just before
    lw = None
    for k in range(n - 1, max(-1, n - 6), -1):
        if insns[k].mnemonic == 'lw':
            lw = k
            break
        if insns[k].address in prologues:
            break
    if lw is None:
        kinds['no-lw'] += 1
        continue
    ops = op_list(insns[lw])
    m = None
    if len(ops) == 2 and ops[1].endswith(')'):
        m = ops[1]
    if not m:
        kinds['lw-unparsed'] += 1
        continue
    breg = m.split('(')[-1].rstrip(')')
    off = m.split('(')[0]
    kind, val, at = resolve_base(lw, breg)
    kinds[kind] += 1
    if kind == 'const':
        const_bases[val] += 1
        lw_sites.append((ins.address, val, off))
        if len(base_samples[val]) < 5:
            base_samples[val].append((ins.address, off))
    elif len(base_samples['NONCONST']) < 4:
        base_samples['NONCONST'].append((ins.address, '%s off=%s reg=%s'
                                         % (kind, off, breg)))

print('=== how jalr feed-lw base registers were formed ===')
for k, c in kinds.most_common():
    print('  %-18s %d' % (k, c))

print('\n=== constant base addresses feeding jalr (%d distinct) ==='
      % len(const_bases))
for b, c in const_bases.most_common(30):
    locs = base_samples[b]
    print('  base 0x%08X  used %2d x   e.g. %s'
          % (b, c, ', '.join('0x%X%s' % (a, o) for a, o in locs[:3])))

if const_bases:
    bs = sorted(const_bases)
    print('\n  span 0x%08X .. 0x%08X' % (bs[0], bs[-1]))
    gaps = sorted(((bs[i + 1] - bs[i], bs[i], bs[i + 1])
                   for i in range(len(bs) - 1)), reverse=True)
    print('  largest gaps:')
    for g, x, y in gaps[:6]:
        print('    0x%X  0x%08X -> 0x%08X' % (g, x, y))

print('\n=== non-constant (vtable/object) samples ===')
for a, s in base_samples['NONCONST']:
    print('  0x%06X: %s' % (a, s))
print('DONE')
