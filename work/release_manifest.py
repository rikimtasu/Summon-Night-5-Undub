"""Release manifest: what does the undub ISO actually change vs the USA ISO?

Self-contained ISO9660 walk (no pycdlib): reads the PVD root record, then
recurses two levels, comparing file names, sizes and content hashes between
the USA source and the undub image. Files with equal size are hashed, which is
how the same-length EBOOT.BIN replacement gets caught.
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

ROOT = paths.ROOT
USA = os.path.join(ROOT, 'Summon Night 5 (USA).iso')
UND = os.path.join(ROOT, 'Summon Night 5 (USA) Undub.iso')


def u32(b, o):
    return struct.unpack('<I', b[o:o + 4])[0]


def read_at(path, off, n):
    with open(path, 'rb') as f:
        f.seek(off)
        return f.read(n)


def list_dir(iso_path, extent, size):
    buf = read_at(iso_path, extent * 2048, size)
    out = []
    p = 0
    while p + 34 <= len(buf):
        len_di = buf[p]
        if len_di == 0:
            nxt = ((p // 2048) + 1) * 2048
            if nxt >= len(buf):
                break
            p = nxt
            continue
        nl = buf[p + 32]
        raw = buf[p + 33:p + 33 + nl]
        flags = buf[p + 25]
        if raw not in (b'\x00', b'\x01'):
            name = raw.decode('latin-1').split(';')[0]
            ext = u32(buf, p + 2)
            ln = u32(buf, p + 10)
            out.append((name, ext, ln, bool(flags & 2)))
        p += len_di
    return out


def walk(iso_path, parts):
    """return {name: (extent, size)} for files under a directory path"""
    pvd = read_at(iso_path, 16 * 2048, 2048)
    root_ext = u32(pvd, 156 + 2)
    root_len = u32(pvd, 156 + 10)
    ext, ln = root_ext, root_len
    for want in parts:
        found = None
        for name, e2, l2, d2 in list_dir(iso_path, ext, ln):
            if name == want and d2:
                found = (e2, l2)
                break
        if not found:
            raise SystemExit('dir not found: %s in %s' % (want, parts))
        ext, ln = found
    res = {}
    for n2, e2, l2, d2 in list_dir(iso_path, ext, ln):
        if not d2:
            res[n2] = (e2, l2)
    return res


def file_sha(iso_path, extent, length):
    h = hashlib.sha256()
    with open(iso_path, 'rb') as f:
        f.seek(extent * 2048)
        rem = length
        while rem:
            b = f.read(min(1 << 20, rem))
            if not b:
                break
            h.update(b)
            rem -= len(b)
    return h.hexdigest()


for parts, label in ((('PSP_GAME', 'SYSDIR'), '/PSP_GAME/SYSDIR'),
                     (('PSP_GAME', 'USRDIR'), '/PSP_GAME/USRDIR')):
    a = walk(USA, parts)
    b = walk(UND, parts)
    print('=== %s ===' % label)
    print('  USA files: %d   undub files: %d' % (len(a), len(b)))
    for k in sorted(set(a) - set(b)):
        print('  only in USA  : %-14s %d B' % (k, a[k][1]))
    for k in sorted(set(b) - set(a)):
        print('  only in undub: %-14s %d B' % (k, b[k][1]))
    size_diff, hash_diff, identical = [], [], 0
    for k in sorted(set(a) & set(b)):
        (ea, la), (eb, lb) = a[k], b[k]
        if la != lb:
            size_diff.append((k, la, lb))
            continue
        sa = file_sha(USA, ea, la)
        sb = file_sha(UND, eb, lb)
        (identical := identical + 1) if sa == sb else hash_diff.append((k, la, sa, sb))
    print('  identical: %d' % identical)
    print('  size differs (%d):' % len(size_diff))
    for k, la, lb in size_diff:
        print('     %-14s %d -> %d' % (k, la, lb))
    print('  same size, content differs (%d):' % len(hash_diff))
    for k, l, sa, sb in hash_diff:
        print('     %-14s %d B  %s -> %s' % (k, l, sa[:16], sb[:16]))
print('DONE', flush=True)
