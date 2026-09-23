import struct, difflib
from disasm_align import disasm, tokens

jp = open('D:/Documents/Default Project/work/psp_ram_jp.bin','rb').read()
usa = open('D:/Documents/Default Project/work/psp_ram_usa3.bin','rb').read()

# code region = units [0, c10) where c10 = block hdr field (data base)
jb_raw = jp[0x08D2D000-0x08000000:0x08D2D000-0x08000000+180224]
ub_raw = usa[0x08D68000-0x08000000:0x08D68000-0x08000000+158152]
jc10 = struct.unpack('<I', jb_raw[16:20])[0]
uc10 = struct.unpack('<I', ub_raw[16:20])[0]
print('JP c10(data base units):', hex(jc10), 'USA:', hex(uc10))

jb = jb_raw[:min(jc10, len(jb_raw)//2)*2]
ub = ub_raw[:min(uc10, len(ub_raw)//2)*2]

dj = disasm(jb, 12)
du = disasm(ub, 12)
print('JP ops', len(dj), 'USA ops', len(du))

tj, tu = tokens(dj), tokens(du)
sm = difflib.SequenceMatcher(None, tj, tu, autojunk=False)
n = 0
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag in ('delete', 'insert'):
        n += 1
        print('== %s jp[%d:%d] usa[%d:%d]' % (tag, i1, i2, j1, j2))
        for k in range(i1, min(i2, i1 + 14)):
            print('   JP ', dj[k])
        for k in range(j1, min(j2, j1 + 14)):
            print('   USA', du[k])
        if (i2 - i1) > 14 or (j2 - j1) > 14:
            print('   ... (truncated, jp +%d usa +%d)' % (i2-i1, j2-j1))
print('indel regions:', n)
