import struct, re
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
d = open('D:/Documents/Default Project/EBOOT_JP_decrypted.bin','rb').read()
SEG_OFF = 0xC0; SEG_FILESZ = 0x21AE00
code = d[SEG_OFF:SEG_OFF+SEG_FILESZ]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN)
table = struct.unpack('<64I', d[SEG_OFF+0x210200:SEG_OFF+0x210200+256])
pat = re.compile(r'sw \S+, (0x[0-9a-f]+)\(\$(?:s0|s1|a0)\)')
for op in range(64):
    h = table[op]
    if not h:
        continue
    stores = set()
    for insn in md.disasm(code[h:h+0x200], h):
        m = pat.match(insn.mnemonic + ' ' + insn.op_str)
        if m:
            stores.add(m.group(1))
        if insn.mnemonic == 'jr' and 'ra' in insn.op_str:
            break
    if stores:
        print('op %d: stores %s' % (op, sorted(stores)))
