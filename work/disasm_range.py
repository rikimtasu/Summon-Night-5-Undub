# -*- coding: utf-8 -*-
"""Generic range disassembler for the decrypted USA EBOOT.

Usage:
    python disasm_range.py 0x147300 0x147560

Resolves lui+addiu materialisations and jal targets, and marks lw/sw offsets
so field accesses such as `lw $a0, 0x60($s0)` are easy to spot. Immediate
handling follows the corrected rule established earlier:

    capstone already prints addiu immediates SIGNED. So
      - a token that is negative is used as-is
      - a non-negative addiu token >= 0x8000 gets -0x10000
      - ori is zero-extended: v & 0xFFFF
The old code double-subtracted and produced garbage for every negative
offset - that bug is what caused the false "save strings are
register-derived" conclusion.

Purpose right now: the controlled three-save diff found

    +0x60   A/B = 1      C = 2      <- chapter, 1 -> 2 (C = start of ch.2)
    +0x64   A/B = 0x1E   C = 0xC8
    +0x6C   A/B = 0      C = 3
    +0x7C   A/B = 4      C = 0x10
    header  +0x04 2->1, +0x10 19->8, +0x14 18->0, +0x18 220->0

and RE_notes records a "chapter-select consumer at 0x147418/0x147468" reading
the intermission pointer table at 0x2331B0. Disassembling that consumer shows
which struct offset it loads, which pins the chapter field independently of
the byte diff.
"""
import os
import sys
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

_HERE = os.path.dirname(os.path.abspath(__file__))
_BOOT = r'EBOOT_USA_decrypted.bin'
# the decrypted USA EBOOT sits at the project root (parent of work/), not in work/
BOOT = os.path.join(os.path.dirname(_HERE), _BOOT) \
    if os.path.isfile(os.path.join(os.path.dirname(_HERE), _BOOT)) \
    else os.path.join(_HERE, _BOOT)
SEG = 0xC0


def imm_of(tok):
    """Correct signed-immediate handling for capstone output."""
    if tok is None:
        return None
    v = int(tok, 0)
    if tok.startswith('-'):
        return v
    if v >= 0x8000:
        v -= 0x10000
    return v


def load():
    return open(BOOT, 'rb').read()


def main(argv):
    if len(argv) < 2:
        print('usage: disasm_range.py <start_fva> <end_fva>')
        return 2
    start, end = int(argv[0], 16), int(argv[1], 16)
    b = load()
    off = start + SEG
    code = b[off:off + (end - start)]
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    pend = {}          # reg -> lui high value
    print('--- disasm 0x%X .. 0x%X ---' % (start, end))
    for ins in md.disasm(code, start):
        toks = ins.op_str.split(',')
        line = '%08X  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str)
        note = ''
        if ins.mnemonic == 'lui' and len(toks) == 2:
            pend[toks[0].strip()] = int(toks[1].strip(), 0) << 16
        elif ins.mnemonic in ('addiu', 'ori') and len(toks) == 3:
            dst, src = toks[0].strip(), toks[1].strip()
            if src in pend:
                hi = pend[src]
                if ins.mnemonic == 'addiu':
                    v = (hi + imm_of(toks[2].strip())) & 0xFFFFFFFF
                else:
                    v = (hi | (int(toks[2].strip(), 0) & 0xFFFF)) & 0xFFFFFFFF
                note = '   ; %s = 0x%08X' % (dst, v)
                pend[dst] = v
                if dst != src:
                    pend.pop(src, None)
            else:
                pend.pop(dst, None)
        elif ins.mnemonic in ('lw', 'sw', 'lbu', 'lhu', 'sb', 'sh'):
            if '(' in ins.op_str:
                try:
                    o, r = ins.op_str.split('(')
                    r = r.rstrip(')')
                    ov = imm_of(o.strip()) or 0
                    note = '   ; [%s%+d] (%s)' % (r, ov, r)
                except Exception:
                    pass
        elif ins.mnemonic == 'jal':
            try:
                note = '   ; -> 0x%X' % int(toks[0].strip(), 16)
            except Exception:
                pass
        print(line + note)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
