import sys
import struct
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm
jp = open(r'D:\Documents\Default Project\work\psp_ram_jp.bin', 'rb').read()
usa = open(r'D:\Documents\Default Project\work\psp_ram_usa3.bin', 'rb').read()
jb = jp[0x08D2D000 - 0x08000000:0x08D2D000 - 0x08000000 + 180224]
ub = usa[0x08D68000 - 0x08000000:0x08D68000 - 0x08000000 + 158152]
jc10 = struct.unpack('<I', jb[16:20])[0]
uc10 = struct.unpack('<I', ub[16:20])[0]
jd = disasm(jb[:jc10 * 2], 12)
ud = disasm(ub[:uc10 * 2], 12)
jby = {t[0]: t for t in jd}
uby = {t[0]: t for t in ud}


def gs(blk, c10, idx):
    bo = (c10 + idx) * 2
    s = []
    p = bo
    while p < len(blk) and blk[p] != 0:
        s.append(blk[p])
        p += 1
        if len(s) > 120:
            break
    return bytes(s)


out = []
out.append('JP 33100-33500:')
for t in jd:
    if 33100 <= t[0] <= 33500 and t[1] == 52 and t[2] == 1 and t[4]:
        if t[4][0] == 214:
            p = jby.get(t[0] - 2)
            arg = p[4][0] if p is not None and p[1] == 50 and p[4] else '?'
            out.append('  VOICE u%d arg=%s' % (t[0], arg))
        elif t[4][0] == 195:
            p = jby.get(t[0] - 2)
            if p is not None and p[1] == 50 and p[2] == 5 and p[4]:
                s = gs(jb, jc10, p[4][0]).decode('utf-8', 'replace')
            else:
                s = '?'
            out.append('  text u%d: %s' % (t[0], s[:80]))
out.append('USA 29970-30210:')
for t in ud:
    if 29970 <= t[0] <= 30210 and t[1] == 52 and t[2] == 1 and t[4]:
        if t[4][0] == 214:
            out.append('  VOICE u%d (kept)' % t[0])
        elif t[4][0] == 195:
            p = uby.get(t[0] - 2)
            if p is not None and p[1] == 50 and p[2] == 5 and p[4]:
                s = gs(ub, uc10, p[4][0]).decode('utf-8', 'replace')
            else:
                s = '?'
            out.append('  text u%d: %s' % (t[0], s[:80]))
open(r'D:\Documents\Default Project\work\namescene.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('written')
