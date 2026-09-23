"""Completeness audit 'after prologue':
A) multiset proof that the captured block's deleted sites are ALL in the table
   (JP sites == USA sites + table sites, per form; catches duplicate-id skips
    that build_v3_table's uc.get(v,0)==0 filter would miss),
B) locate 02.DAT / 10.DAT in both ISOs and find the block inside them
   (first step to scanning ALL other script entries for deleted voice sites).
"""
import struct, os, sys, collections
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

W = r'D:\Documents\Default Project\work'
ROOT = r'D:\Documents\Default Project'
USA_ISO = os.path.join(ROOT, 'Summon Night 5 (USA).iso')
JP_ISO = os.path.join(ROOT, 'Summon Night 5 (JP).iso')


def u32(b, o):
    return struct.unpack('<I', b[o:o + 4])[0]


# ---------------- Phase A ----------------
print('===== PHASE A: within-block multiset proof =====')
jp = open(os.path.join(W, 'psp_ram_jp.bin'), 'rb').read()
usa = open(os.path.join(W, 'psp_ram_usa3.bin'), 'rb').read()
jb = jp[0xD2D000:0xD2D000 + 180224]
ub = usa[0xD68000:0xD68000 + 158152]
jc10 = u32(jb, 16)
uc10 = u32(ub, 16)
print('c10 JP %d USA %d | sizes JP %d USA %d' % (jc10, uc10, len(jb), len(ub)))
jd = disasm(jb[:jc10 * 2], 12)
ud = disasm(ub[:uc10 * 2], 12)
print('tokens JP %d USA %d | last unit JP %s USA %s (c10=%s/%s)'
      % (len(jd), len(ud), jd[-1][0], ud[-1][0], jc10, uc10))


def sites(d):
    """multiset (kind, vid) for CALL214 sites; 'other' = unrecognized arg form"""
    c = collections.Counter()
    other = []
    n195 = 0
    for k, t in enumerate(d):
        if t[1] == 52 and t[2] == 1 and t[4]:
            if t[4][0] == 195:
                n195 += 1
            elif t[4][0] == 214:
                p = d[k - 1] if k >= 1 else None
                if p and p[1] == 50 and p[2] == 10 and p[4]:
                    c[('const', p[4][0])] += 1
                elif p and p[1] == 50 and p[2] == 11:
                    c[('f2', p[3] - 1)] += 1
                elif p and p[1] == 50 and p[2] == 4 and p[4]:
                    c[('pair', p[4][0])] += 1
                else:
                    other.append((t[0], None if p is None else (p[1], p[2], p[3], p[4])))
    return c, other, n195


jcs, jo, j195 = sites(jd)
ucs, uo, u195 = sites(ud)
print('CALL195 lines: JP %d USA %d' % (j195, u195))
if jo:
    print('JP other-form CALL214 (%d):' % len(jo), jo[:8])
if uo:
    print('USA other-form CALL214 (%d):' % len(uo), uo[:8])


def bykind(c, kind):
    return collections.Counter({v: n for (k, v), n in c.items() if k == kind})


table = []
with open(os.path.join(W, 'v3_entries.txt')) as f:
    for line in f:
        a = line.split()
        if len(a) >= 2:
            table.append((int(a[0]), int(a[1])))
tv = collections.Counter(v for _, v in table)
t_const = collections.Counter({v: n for v, n in tv.items() if v >= 15})
t_f2 = collections.Counter({v: n for v, n in tv.items() if v < 15})
print('table: %d entries (const %d, f2 %d)'
      % (len(table), sum(t_const.values()), sum(t_f2.values())))


def cmp_multiset(name, a, b, blabel):
    if a == b:
        print('  OK  %-6s %s == %s (%d sites)' % (name, name, blabel, sum(a.values())))
        return True
    miss = a - b      # in a, not covered by b  -> missing from table/USA
    extra = b - a     # b has more than a       -> suspicious
    print('  FAIL %-s: uncovered JP sites %s | extra %s-side sites %s'
          % (name, dict(miss), blabel, dict(extra)))
    return False


print('multiset checks (Counter subtraction = uncovered JP sites):')
ok = True
ok &= cmp_multiset('const', bykind(jcs, 'const'),
                   bykind(ucs, 'const') + t_const, 'USA+table')
ok &= cmp_multiset('f2', bykind(jcs, 'f2'), bykind(ucs, 'f2') + t_f2, 'USA+table')
ok &= cmp_multiset('pair', bykind(jcs, 'pair'), bykind(ucs, 'pair'), 'USA')
print('PHASE A:', 'ALL COVERED' if ok else 'GAP FOUND')
print('  JP const %d / USA const %d | JP f2 %d / USA f2 %d | JP pair %d / USA pair %d'
      % (sum(bykind(jcs, 'const').values()), sum(bykind(ucs, 'const').values()),
         sum(bykind(jcs, 'f2').values()), sum(bykind(ucs, 'f2').values()),
         sum(bykind(jcs, 'pair').values()), sum(bykind(ucs, 'pair').values())))


# ---------------- Phase B ----------------
print()
print('===== PHASE B: locate script containers in ISOs =====')


def find_in_file(path, needle, lo=0, hi=None, chunk=8 << 20):
    hits = []
    L = len(needle)
    if L == 0:
        return hits
    if hi is None:
        hi = os.path.getsize(path)
    with open(path, 'rb') as f:
        base = lo
        f.seek(lo)
        tail = b''
        remaining = hi - lo
        while remaining > 0:
            buf = f.read(min(chunk, remaining))
            if not buf:
                break
            data = tail + buf
            start = base - len(tail)
            off = 0
            while True:
                i = data.find(needle, off)
                if i < 0:
                    break
                hits.append(start + i)
                off = i + 1
            tail = data[-(L - 1):]
            base += len(buf)
            remaining -= len(buf)
    return hits


def iso_file(iso, name):
    """find ISO9660 dir record for name; return (byte offset, size) of largest match.
    Layout: len@0, extent LE@2/BE@6, size LE@10/BE@14, flags@25, namelen@32, name@33."""
    nb = name.encode()
    hits = find_in_file(iso, nb)
    best = None
    with open(iso, 'rb') as f:
        for pos in hits:
            rs = pos - 33
            if rs < 0:
                continue
            f.seek(rs)
            rec = f.read(64)
            if not rec or len(rec) < 40:
                continue
            namelen = rec[32]
            if namelen not in (6, 8, 10):
                continue
            nm = rec[33:33 + namelen].split(b';')[0]
            if nm != nb:
                continue
            extent = u32(rec, 2)
            size = u32(rec, 10)
            if int.from_bytes(rec[6:10], 'big') != extent or \
               int.from_bytes(rec[14:18], 'big') != size:
                continue
            if extent == 0 or size == 0 or size > (1 << 30):
                continue
            print('  dir rec @%d: name=%s extent=%d(=iso %d) size=%d'
                  % (rs, nm, extent, extent * 2048, size))
            if best is None or size > best[1]:
                best = (extent * 2048, size)
    return best


def header_info(f, off, label, count_expect):
    f.seek(off)
    hdr = f.read(128)
    u32s = struct.unpack('<32I', hdr)
    cnt = [(i * 4, v) for i, v in enumerate(u32s[:17]) if v == count_expect]
    print('%s header[0:68] u32s:' % label, u32s[:17])
    print('  count field candidate (==%d):' % count_expect, cnt)
    return cnt


report = {}
for label, iso, cnt_expect in (('USA', USA_ISO, 24221), ('JP', JP_ISO, 24029)):
    for dat in ('02.DAT', '10.DAT'):
        loc = iso_file(iso, dat)
        if loc is None:
            print('%s %s: NOT FOUND' % (label, dat))
            continue
        off, size = loc
        print('%s %s: offset %d size %d' % (label, dat, off, size))
        report[(label, dat)] = (iso, off, size)
        if dat == '02.DAT':
            with open(iso, 'rb') as f:
                header_info(f, off, '  %s 02' % label, cnt_expect)

# find our block inside each container
print()
print('-- block byte search --')
needles = {
    'hdr0': ub[0:40],
    'tok24': ub[24:64],
    'pool0': ub[uc10 * 2:uc10 * 2 + 80],
    'tok4k': ub[0x1000:0x1040],
}
jneedles = {
    'hdr0': jb[0:40],
    'tok24': jb[24:64],
    'pool0': jb[jc10 * 2:jc10 * 2 + 80],
    'tok4k': jb[0x1000:0x1040],
}
for label, need in (('USA', needles), ('JP', jneedles)):
    for dat in ('02.DAT', '10.DAT'):
        if (label, dat) not in report:
            continue
        iso, off, size = report[(label, dat)]
        for kn, nd in need.items():
            hits = find_in_file(iso, nd, lo=off, hi=off + size)
            if hits:
                print('%s %s: needle %-6s hits %s' % (label, dat, kn, ['%d (dat+%d)' % (h, h - off) for h in hits[:4]]))
