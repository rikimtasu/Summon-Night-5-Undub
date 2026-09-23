import struct, difflib
from disasm_align import disasm, tokens
jp = open('D:/Documents/Default Project/work/psp_ram_jp.bin','rb').read()
usa = open('D:/Documents/Default Project/work/psp_ram_usa3.bin','rb').read()
jb = jp[0x08D2D000-0x08000000+16:][:180224-16]
ub = usa[0x08D68000-0x08000000+16:][:158152-16]
dj = disasm(jb, 4)
du = disasm(ub, 4)
tj, tu = tokens(dj), tokens(du)
sm = difflib.SequenceMatcher(None, tj, tu, autojunk=False)
for tag,i1,i2,j1,j2 in sm.get_opcodes():
    if tag in ('delete','insert'):
        print(f'== {tag} jp[{i1}:{i2}] usa[{j1}:{j2}]')
        for k in range(i1, min(i2, i1+12)):
            print('   JP ', dj[k])
        for k in range(j1, min(j2, j1+12)):
            print('   USA', du[k])
        if (i2-i1) > 12 or (j2-j1) > 12:
            print('   ... (truncated)')
print('done')
