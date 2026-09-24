# -*- coding: utf-8 -*-
"""Property fields that belong to the *save* object, with their context.

    getter  0x1A996C(obj, id) -> *( *(obj+8) + id*4 )
    setter  0x1A9958(obj, id, val)

property[i] lives at DATA.BIN[0x10 + i*4] for i = 0..229, so for the save
object an id names a file offset directly.  But 0x1A996C/0x1A9958 are generic
four-instruction primitives used on dozens of unrelated objects, and a site on
any of those reports an id that means nothing for our file (scan_accessors.py
naively reported every one of them).

So: simulate a window of instructions forward up to and including the branch
delay slot, and keep a site only if $a0 ends up holding the save wrapper

    0x87E30 + 0x664 = 0x88494

which is what `lui $a0,8 / addiu $a0,0x7E30 / addiu $a0,0x664` materialises.
Forward simulation also yields $a1 exactly as the callee sees it (the id is
frequently set in the delay slot, which a backwards walk never sees) and
resolves addresses in the string/rodata region so nearby text can name the
field.

Cross-reference against property_diff.py, which gives each id's values in the
chapter-1 controls (A/B) versus the chapter-2 save (C).

Usage: python scan_save_fields.py [id ...]
"""
import os
import sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

_HERE = os.path.dirname(os.path.abspath(__file__))
_BOOT = 'EBOOT_USA_decrypted.bin'
BOOT = os.path.join(os.path.dirname(_HERE), _BOOT) \
    if os.path.isfile(os.path.join(os.path.dirname(_HERE), _BOOT)) \
    else os.path.join(_HERE, _BOOT)
SEG = 0xC0
CODE_END = 0x21121C

GETTER, SETTER = 0x1A996C, 0x1A9958
SAVE_OBJ = 0x87E30 + 0x664            # 0x88494

STR_LO, STR_HI = 0x210000, 0x246000   # strings/rodata; fva -> file = +SEG

WINDOW = 160                           # instructions simulated before the call
AFTER = 16                             # instructions of context shown after

# caller-saved set: a jal may destroy these, so they must not survive a call
CALLER = ('$v0', '$v1', '$a0', '$a1', '$a2', '$a3',
          '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7',
          '$t8', '$t9', '$ra', '$at')

UNKNOWN = object()


def imm(tok):
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
    if end < 0 or not 0 < end - fo <= 96:
        return None
    raw = d[fo:end]
    if not all(0x20 <= c < 0x7F for c in raw):
        return None
    return raw.decode('latin-1')


def step(regs, addr, m, ops, d, strings):
    """Apply one instruction to the register file; record any string built."""
    toks = [t.strip() for t in ops.split(',')]
    if m == 'lui' and len(toks) == 2:
        regs[toks[0]] = int(toks[1], 0) << 16
        return
    if m in ('addiu', 'ori') and len(toks) == 3:
        dst, src = toks[0], toks[1]
        base = regs.get(src, UNKNOWN)
        if base is UNKNOWN:
            regs[dst] = UNKNOWN
        elif m == 'ori':
            regs[dst] = (base | (int(toks[2], 0) & 0xFFFF)) & 0xFFFFFFFF
        else:
            regs[dst] = (base + imm(toks[2])) & 0xFFFFFFFF
        v = regs[dst]
        if v is not UNKNOWN:
            s = read_str(d, v)
            if s:
                strings.append((addr, v, s))
        return
    if m == 'move' and len(toks) == 2:
        regs[toks[0]] = regs.get(toks[1], UNKNOWN)
        return
    if m == 'addu' and len(toks) == 3 and toks[2] == '$zero':
        regs[toks[0]] = regs.get(toks[1], UNKNOWN)
        return
    if m == 'addu' and len(toks) == 3 and toks[1] == '$zero':
        regs[toks[0]] = regs.get(toks[2], UNKNOWN)
        return
    if not toks or not toks[0].startswith('$'):
        return
    dst = toks[0]
    if m in ('lw', 'lh', 'lhu', 'lb', 'lbu', 'lwu', 'lwl', 'lwr',
             'll', 'lwc1', 'ldc1'):
        regs[dst] = UNKNOWN
    elif m in ('jal', 'jalr'):
        # a call clobbers every caller-saved register; callee-saved $s*,$fp
        # survive, which is exactly why $s4 keeps 0x88494 across a function
        regs['$ra'] = UNKNOWN
        for r in CALLER:
            regs[r] = UNKNOWN
    elif m.startswith('b') or m.startswith('s') and m in ('sw', 'sh', 'sb'):
        pass
    elif m in ('sw', 'sh', 'sb', 'swl', 'swr', 'sc', 'swc1', 'sdc1', 'sd',
               'nop'):
        pass
    else:
        # arithmetic / logic / moves we do not model define an unknown value
        regs[dst] = UNKNOWN


def main(argv):
    filt = set(int(x, 0) for x in argv) if argv else None

    d = open(BOOT, 'rb').read()
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    insns = {}
    for ins in md.disasm(d[SEG:SEG + CODE_END], 0):
        insns[ins.address] = (ins.mnemonic, ins.op_str)
    addrs = sorted(insns)
    idx = {a: n for n, a in enumerate(addrs)}

    save_sites, other = [], 0

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
        i = idx[a]
        lo = max(0, i - WINDOW)

        # $zero must be modelled, or `ori $a1,$zero,N` (the common id shape)
        # resolves to unknown instead of N
        regs, strings = {'$zero': 0, '$at': UNKNOWN}, []
        for k in range(lo, min(len(addrs), i + 2)):      # +2 = include delay slot
            addr = addrs[k]
            step(regs, addr, insns[addr][0], insns[addr][1], d, strings)

        obj = regs.get('$a0', UNKNOWN)
        pid = regs.get('$a1', UNKNOWN)
        if obj != SAVE_OBJ:
            other += 1
            continue

        # context after the call, for the semantics
        ctx_regs, ctx_strings = {'$zero': 0}, []
        ctx_lines = []
        for k in range(max(0, i - 4), min(len(addrs), i + AFTER + 1)):
            addr = addrs[k]
            mm, oo = insns[addr]
            step(ctx_regs, addr, mm, oo, d, ctx_strings)
            ctx_lines.append('%08X  %-8s %s' % (addr, mm, oo))

        save_sites.append(dict(
            kind='get' if tgt == GETTER else 'set',
            addr=a,
            pid=pid if isinstance(pid, int) else None,
            strings=strings + ctx_strings,
            ctx=ctx_lines,
        ))

    # ----------------------------------------------------------------- report
    print('=' * 78)
    print('PROPERTY FIELDS ACCESSED ON THE SAVE OBJECT  (obj = 0x%X)' % SAVE_OBJ)
    print('getter 0x1A996C(obj,id) -> DATA.BIN[0x10 + id*4],  ids 0..229')
    print('=' * 78)
    print('save-object sites: %-4d   other-object sites (discarded): %d'
          % (len(save_sites), other))
    print()

    by_id = {}
    for r in save_sites:
        by_id.setdefault(r['pid'], []).append(r)

    ids = sorted(k for k in by_id if k is not None)
    for pid in ids:
        if filt and pid not in filt:
            continue
        print('-' * 78)
        print('id %-4d   DATA.BIN +0x%05X' % (pid, 0x10 + pid * 4))
        print('-' * 78)
        seen = set()
        for r in by_id[pid]:
            if r['addr'] in seen:
                continue
            seen.add(r['addr'])
            print('  %s at 0x%08X' % (r['kind'], r['addr']))
            for ln in r['ctx']:
                print('       %s' % ln)
            for sa, sv, st in r['strings']:
                print('    str 0x%08X = "%s"' % (sv, st))
            print()
    print('save-object ids: %s' % ', '.join(str(i) for i in ids))
    print('DONE')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
