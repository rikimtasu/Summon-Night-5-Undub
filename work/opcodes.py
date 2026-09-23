import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
d=open('D:/Documents/Default Project/EBOOT_JP_decrypted.bin','rb').read()
SEG_OFF=0xC0; SEG_FILESZ=0x21AE00
code=d[SEG_OFF:SEG_OFF+SEG_FILESZ]
md=Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN)
table=struct.unpack('<64I',d[SEG_OFF+0x210200:SEG_OFF+0x210200+256])
for op in range(64):
    h=table[op]
    if not h: continue
    print(f'== op {op} @ {hex(h)}')
    n=0
    for insn in md.disasm(code[h:h+0x60], h):
        print('   ',hex(insn.address),insn.mnemonic,insn.op_str)
        n+=1
        if n>=10: break
