# -*- coding: utf-8 -*-
"""Find every call to the property getter/setter and name the id it uses.

    0x1A996C(obj, id)  getter:  *( *(obj+8) + id*4 )
    0x1A9958(obj, id, val) setter: writes the same slot

Both are four-instruction primitives, so the id is always an immediate in $a1
just before the `jal`. For each site we look backwards for that immediate and
forwards for context: any address materialised in the string/rodata region is
resolved to its text, which is usually enough to name the field (e.g. a nearby
"Gold" or a table of item names).

Known already:
    id 20 -> DATA.BIN +0x60  CHAPTER  (chapters named from table 0x23311C)
    id 50 -> +0xD8           bucketed against 40/80/100/200

Run this against the ids that property_diff.py reports as progress, and the
surrounding strings supply the semantics.

Usage: python scan_accessors.py [id ...]     # filter to specific ids
"""
import os
import re
import sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

_HERE = os.path.dirname(os.path.abspath(__file__))
BOOT = os.path.join(os.path.dirname(_HERE), 'EBOOT_USA_decrypted.bin')
SEG = 0xC0
CODE_END = 0x21121C

GETTER, SETTER = 0x1A996C, 0x1A9958

# string/rodata live above the code+rodata section; fva -> file offset is +SEG
STR_LO, STR_HI = 0x21C000, 0x250000

_MEM = re.compile(r'(-?(?:0x[0-9a-fA-F]+|\d+))?\((\$\w+)\)')


def imm_of(tok):
    """capstone prints addiu immediates already signed; ori is zero-extended."""
    v = int(tok, 0)
    if tok.startswith('-'):
        return v
    if v >= 0x8000:
        v -= 0x10000
    return v


def read_str(d, fva):
    if not (STR_LO <= fva < STR_HI):
        return None
    fo = fva + SEG
    if fo >= len(d):
        return None
    end = d.find(b'\x00', fo)
    if end < 0 or not 0 < end - fo <= 80:
        return None
    raw = d[fo:end]
    if not all(0x20 <= c < 0x7F for c in raw):
        return None
    return raw.decode('latin-1')


def main(argv):
    filt = set(int(x, 0) for x in argv) if argv else None

    d = open(BOOT, 'rb').read()
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    code = d[SEG:SEG + CODE_END]
    insns = {}
    for ins in md.disasm(code, 0):
        insns[ins.address] = (ins.mnemonic, ins.op_str)

    addrs = sorted(insns)
    idx_of = {a: n for n, a in enumerate(addrs)}

    def resolve_back(a, n=14):
        """Find the value of $a1 at the moment the callee runs.

        MIPS delay slot: the id is very often set by the instruction *after*
        the `jal` (e.g. `jal 0x1a996c` / `ori $a1, $zero, 0x14`), so a purely
        backwards walk never sees it — chapter, id 20, is exactly that shape.
        Check the delay slot first, then walk backwards.
        """
        start = idx_of.get(a)
        if start is None:
            return None, None
        hi = {}
        order = [start + 1] + list(range(start - 1, max(-1, start - n), -1))
        for k in order:
            if k < 0 or k >= len(addrs):
                continue
            addr = addrs[k]
            m, ops = insns[addr]
            toks = [t.strip() for t in ops.split(',')]
            if m == 'lui' and len(toks) == 2:
                hi[toks[0]] = int(toks[1], 0) << 16
            elif m in ('addiu', 'ori') and len(toks) == 3:
                dst, src = toks[0], toks[1]
                if m == 'ori' and src == '$zero' and dst == '$a1':
                    return int(toks[2], 0) & 0xFFFF, 'ori $a1 (delay slot)' \
                        if k == start + 1 else 'ori $a1'
                if src == '$zero' and dst == '$a1':
                    tag = ' (delay slot)' if k == start + 1 else ''
                    return imm_of(toks[2]) & 0xFFFFFFFF, '%s $a1%s' % (m, tag)
                if src in hi and dst == '$a1':
                    v = (hi[src] + imm_of(toks[2])) & 0xFFFFFFFF \
                        if m == 'addiu' else hi[src] | (int(toks[2], 0) & 0xFFFF)
                    return v, 'materialised'
            elif m == 'move' and len(toks) == 2 and toks[0] == '$a1':
                return None, 'register $a1 = %s (not an immediate)' % toks[1]
        return None, 'no immediate found'

    def context(a, before=4, after=9):
        """Print the window around a call, resolving string addresses."""
        start = idx_of.get(a, 0)
        lo = max(0, start - before)
        hi = min(len(addrs), start + after + 1)
        out = []
        pend = {}
        for k in range(lo, hi):
            addr = addrs[k]
            m, ops = insns[addr]
            toks = [t.strip() for t in ops.split(',')]
            note = ''
            if m == 'lui' and len(toks) == 2:
                pend[toks[0]] = int(toks[1], 0) << 16
            elif m in ('addiu', 'ori') and len(toks) == 3:
                dst, src = toks[0], toks[1]
                if src in pend:
                    v = (pend[src] + imm_of(toks[2])) & 0xFFFFFFFF \
                        if m == 'addiu' else \
                        pend[src] | (int(toks[2], 0) & 0xFFFF)
                    pend[dst] = v
                    s = read_str(d, v)
                    if s:
                        note = '   ; str "%s"' % s
                    elif 0x210000 <= v <= 0x260000:
                        note = '   ; addr 0x%X' % v
            mark = '>>' if addr == a else '  '
            out.append('%s %08X  %-8s %s%s' % (mark, addr, m, ops, note))
        return out

    found = {}
    for a in addrs:
        m, ops = insns[a]
        if m != 'jal':
            continue
        try:
            tgt = int(ops.split(',')[0].strip(), 16)
        except ValueError:
            continue
        if tgt not in (GETTER, SETTER):
            continue
        val, how = resolve_back(a)
        kind = 'get' if tgt == GETTER else 'set'
        try:
            pid = int(val)
        except (TypeError, ValueError):
            pid = None
        if pid is None or (filt and pid not in filt):
            key = pid if pid is not None else how
            found.setdefault((kind, key), []).append((a, how))

        # collect for the summary regardless of filter
        found.setdefault(('__all__', pid if pid is not None else how), []) \
            .append((kind, a, how))

    # ---- detailed report, grouped by id -----------------------------------
    ids = sorted(set(k[1] for k in found if k[0] == '__all__'
                     and isinstance(k[1], int)))
    print('=' * 78)
    print('ACCESSOR CALL SITES BY PROPERTY ID')
    print('=' * 78)
    print('getter 0x1A996C = *( *(obj+8) + id*4 )   setter 0x1A9958 writes it')
    print()
    for pid in ids:
        if filt and pid not in filt:
            continue
        sites = found.get(('__all__', pid), [])
        print('-' * 78)
        print('id %-4d  file offset 0x%05X   %d call site(s)'
              % (pid, 0x10 + pid * 4, len(sites)))
        print('-' * 78)
        seen = set()
        for kind, a, how in sites:
            if (kind, a) in seen:
                continue
            seen.add((kind, a))
            print('  %s at 0x%08X   [%s]' % (kind, a, how))
            for line in context(a):
                print('      %s' % line)
        print()
    print('ids seen: %s' % ', '.join(str(i) for i in ids))
    print('DONE')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
