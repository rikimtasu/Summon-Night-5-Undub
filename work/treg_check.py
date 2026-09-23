import re
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
usa = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
SEG = 0xC0
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)


def t_access(fva_lo, fva_hi):
    w = set()
    r = set()
    pat = re.compile(r'\$(\w+)')
    for insn in md.disasm(usa[SEG + fva_lo:SEG + fva_hi], fva_lo):
        s = insn.op_str
        dest = None
        m = pat.match(s)
        if m and insn.mnemonic not in ('sw', 'sb', 'sh', 'swc1', 'jalr',
                                       'beq', 'bne', 'beql', 'bnel', 'jr',
                                       'jal', 'mult', 'div'):
            dest = m.group(1)
        reads = set(pat.findall(s))
        if dest and dest in reads:
            reads.discard(dest)
        if dest in ('t0', 't1', 't2', 't3'):
            w.add(dest)
        for x in reads:
            if x in ('t0', 't1', 't2', 't3'):
                r.add(x)
    return r, w


r1, w1 = t_access(0xDE3E8, 0xDE430)
r2, w2 = t_access(0xDE438, 0xDE548)
print('pre-hook t-reg writes:', sorted(w1), 'reads:', sorted(r1))
print('post-hook t-reg reads:', sorted(r2), 'writes:', sorted(w2))
print('DANGER (written pre, read post, not rewritten post):', sorted((w1 & r2) - w2))
