import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
jp = open(r'D:\Documents\Default Project\EBOOT_JP_decrypted.bin', 'rb').read()
SEG = 0xC0
code = jp[SEG:SEG + 0x21AE00]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
# pattern: lw R,8(base) ... addiu X,zero,-1 ... beq R,X,tgt  within 12 instrs
for i in range(0xBF000, 0xC2000, 4):
    w = struct.unpack('<I', code[i:i + 4])[0]
    if (w >> 26) == 0x23 and (w & 0xFFFF) == 8:
        rt = (w >> 16) & 31
        # look ahead 12 instr for addiu *,zero,-1 then beq rt
        for k in range(1, 13):
            w2 = struct.unpack('<I', code[i + k * 4:i + k * 4 + 4])[0]
            if w2 == (0x24000000 | 0xFFFFFFFF & 0xFFFF) or \
               ((w2 >> 26) == 0x09 and (w2 & 0xFFFF) == 0xFFFF):
                r2 = (w2 >> 16) & 31
                for m in range(k + 1, min(k + 6, 14)):
                    w3 = struct.unpack('<I', code[i + m * 4:i + m * 4 + 4])[0]
                    if (w3 >> 26) == 0x04 and ((w3 >> 21) & 31) == rt and ((w3 >> 16) & 31) == r2:
                        print('replay-check candidate at', hex(i),
                              'lw->beq(-1) | next instrs:')
                        for insn in md.disasm(code[i:i + 0x40], i):
                            print('   ', hex(insn.address), insn.mnemonic, insn.op_str)
                        print()
                        break
                break
print('done')
