import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
usa = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
SEG = 0xC0
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
code = usa[SEG:SEG + 0x21AE00]
# lw R1,0x30(R2), R2 != sp(29); then within 12 instr: lw R3,0x1C(R1)
for i in range(0, len(code) - 64, 4):
    w = struct.unpack('<I', code[i:i + 4])[0]
    if (w >> 26) == 0x23 and (w & 0xFFFF) == 0x30:
        rs, rt = (w >> 21) & 31, (w >> 16) & 31
        if rs == 29:
            continue
        for k in range(1, 13):
            w2 = struct.unpack('<I', code[i + k * 4:i + k * 4 + 4])[0]
            if (w2 >> 26) == 0x23 and (w2 & 0xFFFF) == 0x1C and ((w2 >> 21) & 31) == rt:
                ins = list(md.disasm(code[i:i + 4], i))
                ins2 = list(md.disasm(code[i + k * 4:i + k * 4 + 4], i + k * 4))
                print('fva', hex(i), ins[0].mnemonic, ins[0].op_str,
                      '-> +', k, ins2[0].mnemonic, ins2[0].op_str)
                break
print('done')
