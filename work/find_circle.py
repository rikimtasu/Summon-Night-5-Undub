import struct
usa = open(r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin', 'rb').read()
SEG = 0xC0
# andi rt, 0x2000 (circle button mask checks)
print('andi *,0x2000 sites:')
n = 0
for i in range(SEG, SEG + 0x21AE00 - 4, 4):
    w = struct.unpack('<I', usa[i:i + 4])[0]
    if (w >> 26) == 0x0C and (w & 0xFFFF) == 0x2000:
        print('  ', hex(i - SEG))
        n += 1
        if n >= 30:
            break
print('shown', n)
