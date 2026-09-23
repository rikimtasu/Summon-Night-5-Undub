import re
import struct
from difflib import SequenceMatcher
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
jp = open(r'D:\Documents\Default Project\EBOOT_JP_decrypted.bin', 'rb').read()
usa = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
SEG = 0xC0
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)


def norm(fva_start, fva_end, data):
    out = []
    for insn in md.disasm(data[SEG + fva_start:SEG + fva_end], fva_start):
        s = insn.mnemonic + ' ' + insn.op_str
        # normalize hex immediates / addresses to #
        s = re.sub(r'0x[0-9a-f]+', '#', s)
        s = re.sub(r'-0x[0-9a-f]+', '#', s)
        out.append(s)
    return out


# USA replay fn: find end (jr ra balancing? just take to 0xDE600)
# JP replay fn: 0xC08F4 to similar length. Find JP fn end: next prologue after 0xC08F4?
def fn_end(data, start, limit=0x400):
    for a in range(start + 8, start + limit, 4):
        w = struct.unpack('<I', data[SEG + a:SEG + a + 4])[0]
        if w == 0x03E00008:  # jr ra
            # check epilogue pattern (addiu sp before?)
            return a + 8
    return start + limit


ue = fn_end(usa, 0xDE3E8)
je = fn_end(jp, 0xC08F4)
print('USA replay fn range:', hex(0xDE3E8), '-', hex(ue))
print('JP replay fn range:', hex(0xC08F4), '-', hex(je))
u = norm(0xDE3E8, ue, usa)
j = norm(0xC08F4, je, jp)
print('USA instrs:', len(u), 'JP instrs:', len(j))
sm = SequenceMatcher(None, j, u, autojunk=False)
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag != 'equal':
        print(f'--- {tag} JP[{i1}:{i2}] USA[{j1}:{j2}]')
        for i in range(i1, min(i2, i1 + 12)):
            print('   JP :', j[i])
        for i in range(j1, min(j2, j1 + 12)):
            print('   USA:', u[i])
        if max(i2 - i1, j2 - j1) > 12:
            print('   ... (%d vs %d instrs)' % (i2 - i1, j2 - j1))
