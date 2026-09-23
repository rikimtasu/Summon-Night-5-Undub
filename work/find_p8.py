import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
usa = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
SEG = 0xC0
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
print('lw *,8(*) in backlog range DD000-E1000:')
for i in range(0xDD000, 0xE1000, 4):
    w = struct.unpack('<I', usa[SEG + i:SEG + i + 4])[0]
    if (w >> 26) == 0x23 and (w & 0xFFFF) == 8:
        ins = list(md.disasm(usa[SEG + i:SEG + i + 12], i))
        print('  ', hex(i), ins[0].mnemonic, ins[0].op_str, '|',
              ins[1].mnemonic, ins[1].op_str if len(ins) > 1 else '')
