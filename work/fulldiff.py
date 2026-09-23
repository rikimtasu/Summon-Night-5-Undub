import struct, difflib
from disasm_align import disasm, tokens
jp = open('D:/Documents/Default Project/work/psp_ram_jp.bin','rb').read()
usa = open('D:/Documents/Default Project/work/psp_ram_usa3.bin','rb').read()
jb = jp[0x08D2D000-0x08000000+16:][:180224-16]
ub = usa[0x08D68000-0x08000000+16:][:158152-16]
# skip 4-unit block header
dj = disasm(jb, 4)
du = disasm(ub, 4)
print('jp ops:', len(dj), 'usa ops:', len(du))
tj, tu = tokens(dj), tokens(du)
sm = difflib.SequenceMatcher(None, tj, tu, autojunk=False)
print('ratio:', sm.ratio())
diffs = [o for o in sm.get_opcodes() if o[0] != 'equal']
print('diff regions:', len(diffs))
for tag,i1,i2,j1,j2 in diffs[:40]:
    print(f'{tag} jp[{i1}:{i2}] (units {dj[i1][0]}-{dj[i2-1][0] if i2>i1 else "-"}) usa[{j1}:{j2}] (units {du[j1][0]}-{du[j2-1][0] if j2>j1 else "-"})')
    if (i2-i1) <= 8:
        for k in range(i1, i2): print('   JP ', dj[k])
    if (j2-j1) <= 8 and tag != 'delete':
        for k in range(j1, j2): print('   USA', du[k])
    print('---')
