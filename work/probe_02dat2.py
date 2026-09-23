import struct, os
W = r'D:\Documents\Default Project'
WORK = os.path.join(W, 'work')
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


def dump(iso, off, at, n):
    with open(iso, 'rb') as f:
        f.seek(off + at)
        b = f.read(n)
    print('  @%d:' % at, b[:96])
    # run of printable strings
    s = b.split(b'\x00')
    strs = [x for x in s if len(x) >= 4 and all(32 <= c < 127 for c in x)]
    if strs:
        print('    strings:', [x[:40] for x in strs[:8]])


print('== region dumps (USA 02.DAT) ==')
for at in (70, 775056, 775072, 1310720, 2861482, 5585152, 327680):
    dump(U02[0], U02[1], at, 256)
print('== region dumps (JP 02.DAT) ==')
for at in (70, 768912, 768928, 1310720, 5585152):
    dump(J02[0], J02[1], at, 256)

print()
print('== interior needle sweep ==')
ram_jp = open(os.path.join(WORK, 'psp_ram_jp.bin'), 'rb').read()
ram_us = open(os.path.join(WORK, 'psp_ram_usa3.bin'), 'rb').read()
jb = ram_jp[0xD2D000:0xD2D000 + 180224]
ub = ram_us[0xD68000:0xD68000 + 158152]
uc10 = u32(ub, 16); jc10 = u32(jb, 16)
print('USA pool0:', repr(ub[uc10 * 2:uc10 * 2 + 56]))
needles_u = {k: ub[o:o + 32] for k, o in
             (('tok0', 0), ('tok8k', 8000), ('tok40k', 40000), ('tok70k', 70000),
              ('pool0', uc10 * 2), ('pool32k', uc10 * 2 + 32000),
              ('poolend', len(ub) - 64))}
needles_j = {k: jb[o:o + 32] for k, o in
             (('tok0', 0), ('tok8k', 8000), ('tok40k', 40000), ('tok70k', 70000),
              ('pool0', jc10 * 2), ('poolend', len(jb) - 64))}
for lbl, (iso, off, size, cnt), nds in (('USA', U02, needles_u), ('JP', J02, needles_j)):
    for k, nd in nds.items():
        hits = find_in_file(iso, nd, off, off + size)
        tag = ('HIT  %s %-8s dat+%d' % (lbl, k, hits[0] - off)) if hits else ('miss %s %s' % (lbl, k))
        print(' ', tag)
    # also search whole ISO (not just container) for pool0
    hits = find_in_file(iso, nds['pool0'], 0, os.path.getsize(iso))
    print('  whole-ISO pool0', lbl, '->', [h for h in hits[:4]] or 'none')
