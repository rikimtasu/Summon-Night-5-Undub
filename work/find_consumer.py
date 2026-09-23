import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
usa = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
SEG = 0xC0
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
# lw rt,0x1C(rs): candidate voice-field readers. For each, show context and
# whether a nearby jal targets audio/file-ish code.
rds = []
for i in range(SEG, SEG + 0x21AE00 - 4, 4):
    w = struct.unpack('<I', usa[i:i + 4])[0]
    if (w >> 26) == 0x23 and (w & 0xFFFF) == 0x1C:
        rds.append(i - SEG)
print('lw +0x1C count:', len(rds))
for fva in rds:
    # look back up to 12 instr for 'lw rx,0x30' (voiceobj load pattern)
    win = usa[SEG + fva - 48:SEG + fva + 4]
    found30 = False
    for j in range(0, len(win) - 4, 4):
        w = struct.unpack('<I', win[j:j + 4])[0]
        if (w >> 26) == 0x23 and (w & 0xFFFF) == 0x30:
            found30 = True
    if found30:
        ins = list(md.disasm(usa[SEG + fva:SEG + fva + 8], fva))
        print('CANDIDATE fva', hex(fva), ins[0].mnemonic, ins[0].op_str)
