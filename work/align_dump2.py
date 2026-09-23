"""Dump JP text lines with voice-attach markers + USA tail, for manual alignment."""
import struct, sys
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


def getstr(blk, c10, idx, n=140):
    bo = (c10 + idx) * 2
    end = blk.find(b'\x00', bo)
    return blk[bo:end][:n].decode('utf-8', 'replace')


def voice_arg(jd, k):
    """arg of CALL214 at token k: const(f1=10)->ops0, f2-1(f1=11)->f2-1, pair(f1=4)->ops0"""
    p = jd[k - 1]
    if p[1] != 50:
        return '?'
    if p[2] == 10 and p[4]:
        return str(p[4][0])
    if p[2] == 11:
        return 'f2:%d' % (p[2] - 1)  # id in f2 field chain; print raw below
    if p[2] == 4 and p[4]:
        return str(p[4][0])
    return '?'


out = open(r'D:\Documents\Default Project\work\align_dump.txt', 'w', encoding='utf-8')

# ---- JP: text lines ju 25100-33000 with voice markers ----
out.write('=== JP lines (ju 25100-33000): [vN] = line the voice attaches to, set by preceding CALL214 ===\n')
lastv = None
for k, t in enumerate(jd):
    is_call = (t[1] == 52 and t[2] == 1 and t[4])
    if is_call and t[4][0] == 214:
        p = jd[k - 1]
        if p[1] == 50 and p[2] == 11:
            # f2-1 form: op50 f1=11 has width 0 -> token (u,50,11,f2,[]); id = f2-1
            arg = 'id%d' % (p[3] - 1)
        else:
            arg = voice_arg(jd, k)
        lastv = arg
        if 25100 <= t[0] <= 33000:
            out.write('unit %5d <<VOICE v%s>>\n' % (t[0], arg))
        continue
    if is_call and t[4][0] == 195 and k >= 1:
        p = jd[k - 1]
        if p[1] == 50 and p[2] == 5 and p[4]:
            if 25100 <= t[0] <= 33000:
                mk = ('[v%-4s]' % lastv) if lastv is not None else '[    ]'
                out.write('unit %5d %s %s\n' % (t[0], mk, getstr(jb, jc10, p[4][0])))
            lastv = None

# ---- USA tail: unit 39000-41500 ----
out.write('\n=== USA text calls unit 39000-41500 ===\n')
rows = [l.split() for l in open(r'D:\Documents\Default Project\work\v3_entries.txt')]
entries = [(int(r[0]), int(r[1]), int(r[2]), int(r[3])) for r in rows]
by_key = {k: v for (k, v, jx, ux) in entries}
for k, t in enumerate(ud):
    if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195 and k >= 1:
        p = ud[k - 1]
        if p[1] == 50 and p[2] == 5 and p[4] and 39000 <= t[0] <= 41500:
            key = 2 * (uc10 + p[4][0])
            vid = by_key.get(key)
            tag = 'vid=%d' % vid if vid is not None else '**UNATT**'
            out.write('unit %5d key %6d %-10s %s\n' % (t[0], key, tag, getstr(ub, uc10, p[4][0])))
out.close()
print('done')
