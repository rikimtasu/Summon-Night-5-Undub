import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

for tag, path in (('JP', r'D:\Documents\Default Project\EBOOT_JP_decrypted.bin'),
                  ('USA', r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin')):
    d = open(path, 'rb').read()
    SEG = 0xC0
    code = d[SEG:SEG + 0x21AE00]
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    print('==', tag, 'sw-0x1C preceded by lw-0x30 (voice-field stores):')
    for i in range(0, len(code) - 32, 4):
        w = struct.unpack('<I', code[i:i + 4])[0]
        if (w >> 26) == 0x2B and (w & 0xFFFF) == 0x1C:
            rs, rt = (w >> 21) & 31, (w >> 16) & 31
            for k in range(1, 9):
                w2 = struct.unpack('<I', code[i - k * 4:i - k * 4 + 4])[0]
                if (w2 >> 26) == 0x23 and (w2 & 0xFFFF) == 0x30 and ((w2 >> 16) & 31) == rs:
                    ins = list(md.disasm(code[i - k * 4:i + 8], i - k * 4))
                    print('  store at fva', hex(i), '| loader:',
                          ' | '.join('%s %s' % (x.mnemonic, x.op_str) for x in ins[:k + 2]))
                    break
    print()
