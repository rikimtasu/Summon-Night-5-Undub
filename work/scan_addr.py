# -*- coding: utf-8 -*-
"""Find every memory access to a given link-time address across the whole EBOOT.

Usage:
    python scan_addr.py 0x23322C

Purpose
-------
The save layout has been derived as follows.

  1. `0x1A996C(obj, id)` is the property getter:
         lw   $a0, 8($a0)
         sll  $a1, $a1, 2
         addu $a0, $a0, $a1
         lw   $v0, ($a0)          ; *(obj->array + id*4)

  2. The loader at 0x141534 fills that array out of the loaded DATA.BIN:
         lw   $s1, 0x322c($s2)    ; s_pLoadGameData  @ 0x23322C
         move $s4, $s1
         lw   $a2, 0x10($s4)      ; property[i] = *(buf + 0x10 + i*4)
         jal  0x1A9958            ; set(obj, i, val)
         slti $a0, $s5, 0xe6      ; 230 words -> 0x10 .. 0x3A8
         addiu $s4, $s4, 4        ; delay slot

  3. `get(obj, 20)` feeds the chapter-name table at 0x23311C
     ('Ch. 0, First Dream' ... 'Ch. 15, ...', then Ending/Karma/Clear Data).

  => property[i] is at file offset 0x10 + i*4
     => chapter (id 20) is at file offset 0x60.

The one unverified link is that s_pLoadGameData points at the START of the
DATA.BIN buffer rather than some interior struct. If it does, 0x60 is correct;
if it points N bytes in, the chapter offset is 0x60 - N. So this script finds
every write to 0x23322C (and every read) to identify what value is stored
there, plus every access to 0x23311C (the chapter table) to confirm all its
consumers treat it as chapter-indexed.

It also reports accesses to the runtime addresses, since some code may have
been pre-relocated.
"""
import re
import sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

# matches the memory operand of a load/store:  -0x4818($s0)  or  ($s0)
_MEM = re.compile(r'(-?(?:0x[0-9a-fA-F]+|\d+))?\((\$\w+)\)')

BOOT = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
RT = 0x08804000
CODE_END = 0x21121C

REGS = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
        't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
        's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
        't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']


def imm_of(tok):
    """Correct capstone immediate handling: addiu prints already signed."""
    v = int(tok, 0)
    if tok.startswith('-'):
        return v
    if v >= 0x8000:
        v -= 0x10000
    return v


def main(argv):
    want = set()
    for a in argv[1:] if argv else []:
        v = int(a, 16)
        want.add(v)
        want.add((v + RT) & 0xFFFFFFFF)
    if not want:
        print('usage: scan_addr.py <fva> [more fva...]')
        return 2

    d = open(BOOT, 'rb').read()
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    code = d[SEG:SEG + CODE_END]
    reg = {}
    pend_hi = {}
    hits = 0

    for ins in md.disasm(code, 0):
        m, ops = ins.mnemonic, ins.op_str
        toks = [t.strip() for t in ops.split(',')]

        if m == 'lui' and len(toks) == 2:
            pend_hi[toks[0]] = int(toks[1], 0) << 16
            reg[toks[0]] = pend_hi[toks[0]]
            continue

        # effective address of a memory operand  off($reg)
        ea = None
        if m in ('lw', 'sw', 'lbu', 'sb', 'lhu', 'sh', 'lwl', 'swl',
                 'lwr', 'swr'):
            mm = _MEM.search(ops)
            if mm:
                off = imm_of(mm.group(1)) if mm.group(1) else 0
                rn = mm.group(2)
                base = reg.get(rn)
                if base is not None:
                    ea = (base + off) & 0xFFFFFFFF

        if ea is not None and ea in want:
            hits += 1
            kind = 'READ ' if m != 'sw' and not m.startswith('s') else 'WRITE'
            print('%08X  %-6s %-4s  %s' % (ins.address, m, kind, ops))

        # keep register materialisation state roughly in sync
        if m in ('addiu', 'ori') and len(toks) == 3:
            dst, src = toks[0], toks[1]
            if src in pend_hi:
                if m == 'addiu':
                    reg[dst] = (pend_hi[src] + imm_of(toks[2])) & 0xFFFFFFFF
                else:
                    reg[dst] = pend_hi[src] | (int(toks[2], 0) & 0xFFFF)
                pend_hi[dst] = reg[dst]
            elif dst in reg and src == dst:
                reg[dst] = (reg[dst] + imm_of(toks[2])) & 0xFFFFFFFF \
                    if m == 'addiu' else \
                    (reg[dst] | (int(toks[2], 0) & 0xFFFF))
            else:
                reg.pop(dst, None)
                pend_hi.pop(dst, None)
        elif m in ('move', 'addu', 'addiu', 'or') and len(toks) == 3 \
                and toks[2] in reg and toks[1] == toks[2]:
            reg[toks[0]] = reg[toks[2]]
        elif m == 'lw' and len(toks) == 2:
            # pointer load: value unknown
            reg.pop(toks[0], None)
            pend_hi.pop(toks[0], None)
        elif m.startswith('j') and len(toks) == 1:
            pass

    print('--- %d accesses found ---' % hits)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
