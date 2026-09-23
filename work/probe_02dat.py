import struct, os, sys, collections
W = r'D:\Documents\Default Project'
USA_ISO = os.path.join(W, 'Summon Night 5 (USA).iso')
JP_ISO = os.path.join(W, 'Summon Night 5 (JP).iso')
U02 = (USA_ISO, 328826880, 140421120, 24221)
J02 = (JP_ISO, 162758656, 139329536, 24029)


def u32(b, o):
    return struct.unpack('<I', b[o:o + 4])[0]


def find_in_file(path, needle, lo, hi, chunk=8 << 20):
    hits = []; L = len(needle)
    with open(path, 'rb') as f:
        f.seek(lo); base = lo; tail = b''; remaining = hi - lo
        while remaining > 0:
            buf = f.read(min(chunk, remaining))
            if not buf:
                break
            data = tail + buf; start = base - len(tail); off = 0
            while True:
                i = data.find(needle, off)
                if i < 0:
                    break
                hits.append(start + i); off = i + 1
            tail = data[-(L - 1):]; base += len(buf); remaining -= len(buf)
    return hits


# ---- 1. entry table dump ----
for lbl, (iso, off, size, cnt) in (('USA', U02), ('JP', J02)):
    with open(iso, 'rb') as f:
        f.seek(off)
        hdr = f.read(70 + 56 * 4)
        print('== %s 02.DAT header[0:70] u32s ==' % lbl)
        print('  ', struct.unpack('<17I', hdr[:68]))
        print('  entries 0..3 (14 u32 each):')
        for i in range(4):
            e = hdr[70 + i * 56: 70 + (i + 1) * 56]
            print('   ', i, struct.unpack('<14I', e))
        # scan field monotonicity: for each field position, check if values rise with i
        f.seek(off + 70)
        tbl = f.read(cnt * 56)
        print('  field scan over %d entries:' % cnt)
        for fld in range(14):
            vals = [u32(tbl, i * 56 + fld * 4) for i in range(cnt)]
            nz = sum(1 for v in vals if v)
            mono = all(vals[i] <= vals[i + 1] for i in range(0, cnt - 1, 7))
            print('    f%-2d nonzero=%6d min=%-10d max=%-10d first5=%s %s'
                  % (fld, nz, min(vals), max(vals), vals[:5],
                     'MONO~' if mono else ''))

# ---- 2. interior needle sweep ----
print()
print('== interior needle sweep ==')
ram_jp = open(os.path.join(W, r'psp_ram_jp.bin'), 'rb').read()
ram_us = open(os.path.join(W, r'psp_ram_usa3.bin'), 'rb').read()
jb = ram_jp[0xD2D000:0xD2D000 + 180224]
ub = ram_us[0xD68000:0xD68000 + 158152]
uc10 = u32(ub, 16); jc10 = u32(jb, 16)
needles_u = {k: ub[o:o + 32] for k, o in
             (('tok0', 0), ('tok8k', 8000), ('tok40k', 40000), ('tok70k', 70000),
              ('pool0', uc10 * 2), ('pool32k', uc10 * 2 + 32000),
              ('poolend', len(ub) - 64))}
needles_j = {k: jb[o:o + 32] for k, o in
             (('tok0', 0), ('tok8k', 8000), ('tok40k', 40000),
              ('pool0', jc10 * 2), ('poolend', len(jb) - 64))}
print('USA pool0 needle ascii:', repr(ub[uc10 * 2:uc10 * 2 + 48]))
for lbl, (iso, off, size, cnt) in (('USA', U02), ('JP', J02)):
    nds = needles_u if lbl == 'USA' else needles_j
    for k, nd in nds.items():
        hits = find_in_file(iso, nd, off, off + size)
        if hits:
            print('  HIT %s %s -> dat+%d' % (lbl, k, hits[0] - off))

# ---- 3. USRDIR listing ----
print()
print('== USRDIR dir listing ==')


def iso_dir(iso, dirname):
    nb = dirname.encode()
    hits = find_in_file(iso, nb, 0, os.path.getsize(iso))
    best = None
    with open(iso, 'rb') as f:
        for pos in hits:
            rs = pos - 33
            if rs < 0:
                continue
            f.seek(rs); rec = f.read(64)
            if len(rec) < 40:
                continue
            nl = rec[32]
            if nl not in (6, 8, 10, 16):
                continue
            nm = rec[33:33 + nl].split(b';')[0]
            if nm != nb:
                continue
            ext = u32(rec, 2); sz = u32(rec, 10)
            if best is None or sz > best[1]:
                best = (ext * 2048, sz)
    return best


def list_dir(iso, extent, size, limit=4000):
    out = []
    with open(iso, 'rb') as f:
        f.seek(extent); buf = f.read(size)
    p = 0
    while p + 34 < len(buf):
        len_di = buf[p]
        if len_di == 0:
            p += 2048 - (p % 2048)
            continue
        nl = buf[p + 32]
        nm = buf[p + 33:p + 33 + nl]
        ext = u32(buf, p + 2); sz = u32(buf, p + 10)
        flags = buf[p + 25]
        out.append((nm, ext * 2048, sz, flags))
        p += len_di
        if len(out) >= limit:
            break
    return out


for iso, lbl in ((USA_ISO, 'USA'), (JP_ISO, 'JP')):
    loc = iso_dir(iso, 'USRDIR')
    if not loc:
        print(lbl, 'USRDIR not found'); continue
    ents = list_dir(iso, *loc)
    print('%s USRDIR (%d entries):' % (lbl, len(ents)))
    for nm, ext, sz, fl in ents:
        try:
            s = nm.split(b';')[0].decode('ascii')
        except Exception:
            s = repr(nm)
        print('   %-16s off=%-11d size=%-11d %s' % (s, ext, sz, 'DIR' if fl & 2 else ''))
