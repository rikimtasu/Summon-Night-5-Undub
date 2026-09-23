"""Audit v3/v4 voice->text mapping: for each table entry, show the JP line
following the deleted voice (its owning line) vs the USA line it was
attached to. Flags candidates where anchor/text distance is large.
"""
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


def getstr(blk, c10, idx, maxb=160):
    bo = (c10 + idx) * 2
    s = []
    p = bo
    while p < len(blk) and blk[p] != 0:
        s.append(blk[p])
        p += 1
        if len(s) > maxb:
            break
    return bytes(s)


def jp_next_texts(jpu, n=2):
    """Next n JP CALL195 strings after JP unit jpu."""
    out = []
    units = sorted(jby)
    i = units.index(jpu) if jpu in jby else None
    if i is None:
        return out
    for t in jd[i + 1:]:
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195:
            p = jby.get(t[0] - 2)
            if p is not None and p[1] == 50 and p[2] == 5 and p[4]:
                try:
                    out.append(getstr(jb, jc10, p[4][0]).decode('utf-8', 'replace'))
                except Exception:
                    out.append('?')
                if len(out) >= n:
                    break
    return out


def jp_prev_texts(jpu, n=2):
    """Previous n JP CALL195 strings before JP unit jpu."""
    out = []
    units = sorted(jby)
    i = units.index(jpu) if jpu in jby else None
    if i is None:
        return out
    for t in reversed(jd[max(0, i - 12):i]):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195:
            p = jby.get(t[0] - 2)
            if p is not None and p[1] == 50 and p[2] == 5 and p[4]:
                try:
                    out.append(getstr(jb, jc10, p[4][0]).decode('utf-8', 'replace'))
                except Exception:
                    out.append('?')
                if len(out) >= n:
                    break
    out.reverse()
    return out


def usa_text_at(uu):
    t = uby.get(uu)
    if t is None:
        return '?'
    p = uby.get(uu - 2)
    if p is None or p[1] != 50 or p[2] != 5 or not p[4]:
        return '?'
    try:
        return getstr(ub, uc10, p[4][0]).decode('utf-8', 'replace')
    except Exception:
        return '?'


def usa_neighbor_texts(uu):
    """Prev and next USA text-call units around uu (by unit order).
    Returns ((prev_unit, prev_key, prev_text), (next_unit, next_key, next_text))."""
    units = sorted(uby)
    try:
        i = units.index(uu)
    except ValueError:
        return ((None, None, '?'), (None, None, '?'))
    prev = nxt = (None, None, '?')
    for t in reversed(ud[max(0, i - 8):i]):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195:
            p = uby.get(t[0] - 2)
            if p is not None and p[1] == 50 and p[2] == 5 and p[4]:
                prev = (t[0], 2 * (uc10 + p[4][0]), usa_text_at(t[0]))
                break
    for t in ud[i + 1:i + 9]:
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195:
            p = uby.get(t[0] - 2)
            if p is not None and p[1] == 50 and p[2] == 5 and p[4]:
                nxt = (t[0], 2 * (uc10 + p[4][0]), usa_text_at(t[0]))
                break
    return (prev, nxt)


rows = [l.split() for l in open(r'D:\Documents\Default Project\work\v3_entries.txt')]
print('total entries:', len(rows))
with open(r'D:\Documents\Default Project\work\audit.txt', 'w', encoding='utf-8') as out:
    for r in rows:
        key, vid, ju, uu = int(r[0]), r[1], int(r[2]), int(r[3])
        jtexts = jp_next_texts(ju)
        jprev = jp_prev_texts(ju)
        utext = usa_text_at(uu)
        (puu, pkey, uprev), (nuu, nkey, unext) = usa_neighbor_texts(uu)
        j0 = jtexts[0][:60] if jtexts else '-'
        j1 = jtexts[1][:60] if len(jtexts) > 1 else '-'
        jp0 = jprev[0][:60] if jprev else '-'
        jp1 = jprev[1][:60] if len(jprev) > 1 else '-'
        out.write(f'vid={vid} jpu={ju} -> usa={uu} key={key}\n')
        out.write(f'   JP-2: {jp0}\n')
        out.write(f'   JP-1: {jp1}\n')
        out.write(f'   JP+1: {j0}\n')
        out.write(f'   JP+2: {j1}\n')
        out.write(f'   USA-prev: [{puu}/{pkey}] {uprev[:70]}\n')
        out.write(f'   USA     : {utext[:70]}\n')
        out.write(f'   USA-next: [{nuu}/{nkey}] {unext[:70]}\n')
