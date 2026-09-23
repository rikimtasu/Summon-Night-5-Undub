"""v3: map deleted JP voice triggers -> USA text-line keys.

For each JP CALL214 missing in USA (const-arg + f2-1 forms), find the USA
text-display call (CALL195) at the aligned position; emit (c10, offset, voiceid).
"""
import sys, struct, collections
sys.path.insert(0, r'D:\Documents\Default Project\work')
from difflib import SequenceMatcher
from disasm_align import disasm

jp = open(r'D:\Documents\Default Project\work\psp_ram_jp.bin', 'rb').read()
usa = open(r'D:\Documents\Default Project\work\psp_ram_usa3.bin', 'rb').read()
jb = jp[0x08D2D000 - 0x08000000:0x08D2D000 - 0x08000000 + 180224]
ub = usa[0x08D68000 - 0x08000000:0x08D68000 - 0x08000000 + 158152]
jc10 = struct.unpack('<I', jb[16:20])[0]
uc10 = struct.unpack('<I', ub[16:20])[0]
print('c10 JP', jc10, 'USA', uc10)
jd = disasm(jb[:jc10 * 2], 12)
ud = disasm(ub[:uc10 * 2], 12)


def tok(t):
    _, op, f1, f2, ops = t
    if op == 52 and f1 == 1:
        return (op, f1, f2, ops[0] if ops else None)
    if op == 50 and f1 == 4 and ops:
        return (op, f1, f2, ops[0])
    if op == 50 and f1 == 10 and ops:
        return (op, f1, f2, ops[0])
    if op == 53 and ops:
        return (op, f1, ops[0] if ops else None)
    if op in (0, 48, 49, 53, 54):
        return (op, f1)
    return (op, f1, f2)


jt = [tok(t) for t in jd]
ut = [tok(t) for t in ud]
sm = SequenceMatcher(None, jt, ut, autojunk=False)

# USA voice-id multiset (to only insert truly-missing ids)
def usa_voice_ids():
    byu = {t[0]: t for t in ud}
    c = collections.Counter()
    for u, t in sorted(byu.items()):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 214:
            for b in range(1, 5):
                if u - b in byu:
                    p = byu[u - b]
                    if p[1] == 50 and p[2] == 10 and p[4]:
                        c[p[4][0]] += 1
                    elif p[1] == 50 and p[2] == 11:
                        c[('f', p[3])] += 1
                    break
    return c


uc = usa_voice_ids()

# USA text-call positions: list idx k where ud[k] = CALL195 and ud[k-1] = op50 f1=5
usa_text = {}   # list idx k -> str idx operand
for k in range(1, len(ud)):
    t = ud[k]
    if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195:
        p = ud[k - 1]
        if p[1] == 50 and p[2] == 5 and p[4]:
            usa_text[k] = p[4][0]

print('USA text calls:', len(usa_text))

# collect deleted JP voice sites with USA anchors
sites = []  # (voiceid, jp_unit, j_anchor)
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag == 'equal':
        continue
    anchor = j1  # USA list position where JP [i1:i2] maps (delete: j1==j2; replace/insert: j1)
    if tag == 'insert':
        continue
    for i in range(i1, i2):
        t = jd[i]
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 214:
            # find arg push: previous JP unit present
            vid = None
            for b in range(1, 7):
                # find decoded op right before in list
                if i - 1 >= 0:
                    pass
            p = jd[i - 1] if i - 1 >= 0 else None
            if p is None:
                continue
            if p[1] == 50 and p[2] == 10 and p[4]:
                vid = p[4][0]
            elif p[1] == 50 and p[2] == 11:
                vid = ('f', p[3])
            elif p[1] == 50 and p[2] == 4 and p[4]:
                vid = ('pair', p[4][0])
            else:
                vid = ('other', p[1], p[2])
            sites.append((vid, t[0], anchor))

print('deleted CALL214 sites in runs:', len(sites))
byvid = collections.Counter(v for v, _, _ in sites)
print('pair-form in runs:', sum(1 for v, _, _ in sites if isinstance(v, tuple) and v[0] == 'pair'))
print('other-form in runs:', collections.Counter(v for v, _, _ in sites if isinstance(v, tuple) and v[0] == 'other'))

# keep only truly-missing ids
need = [(v, u, a) for (v, u, a) in sites
        if not (isinstance(v, tuple) and v[0] == 'pair') and uc.get(v, 0) == 0]
print('sites needing insert (missing ids):', len(need))

# map each to first USA text call at idx >= anchor (window 400).
# `used` forces spreading when USA merged lines (1 JP voice per USA text call).
used = {}
entries = []
unmapped = []
for (v, u, a) in sorted(need, key=lambda x: x[1]):
    k = None
    for kk in range(a, min(len(ud), a + 400)):
        if kk in usa_text and kk not in used:
            k = kk
            break
    if k is None:
        unmapped.append((v, u, a))
        continue
    used[k] = v
    entries.append((v, u, a, k, usa_text[k]))

print('mapped:', len(entries), 'unmapped:', len(unmapped))
if unmapped:
    print('unmapped sample:', unmapped[:10])

# string helpers
def getstr(blk, c10, idx):
    bo = (c10 + idx) * 2
    s = []
    p = bo
    while p < len(blk) and blk[p] != 0:
        s.append(blk[p])
        p += 1
        if len(s) > 200:
            break
    return bytes(s)

print()
print('samples (vid, jp_unit -> usa text):')
for (v, u, a, k, sidx) in entries[:4] + entries[len(entries)//2:len(entries)//2+2] + entries[-2:]:
    us = getstr(ub, uc10, sidx)
    print('  vid=%s jpu=%s => usa unit %s stridx %s: %r' % (v, u, ud[k][0], sidx, us[:80]))

# save entries: list of (key_offset, voiceid_int)
out = []
for (v, u, a, k, sidx) in entries:
    key = 2 * (uc10 + sidx)
    vid = v[1] - 1 if isinstance(v, tuple) and v[0] == 'f' else v
    out.append((key, vid, u, ud[k][0]))
out.sort()
with open(r'D:\Documents\Default Project\work\v3_entries.txt', 'w') as f:
    for key, vid, ju, uu in out:
        f.write('%d %d %d %d\n' % (key, vid, ju, uu))
print()
print('wrote work/v3_entries.txt with', len(out), 'entries')
vids = [vid for _, vid, _, _ in out]
print('vid range:', min(vids), '..', max(vids))
keys = [k for k, _, _, _ in out]
print('dup keys:', len(keys) - len(set(keys)))
