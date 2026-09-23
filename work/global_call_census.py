"""Global CALL-pattern census over whole RAM of every SN5 state.

CALL195 token = u16(0x0034) + u16(195); CALL214 = u16(0x0034) + u16(214).
Find all hits, cluster by 64KB, then locate the nearest preceding script-block
header (magic 0x10000201/0x10000002) for each cluster.
"""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
STATES = [
    ('ULUS10656_1.01_0.ppst', 'usa'),
    ('ULUS10656_1.01_1.ppst', 'usa'),
    ('ULUS10656_1.01_2.ppst', 'usa'),
    ('ULUS10656_1.01_3.ppst', 'usa'),
    ('ULUS10656_1.01_4.ppst', 'usa'),
    ('NPJH50696_1.01_0.ppst', 'jp'),
    ('NPJH50696_1.01_1.ppst', 'jp'),
    ('NPJH50696_1.01_4.ppst', 'jp'),
]


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory'
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


def find_all(blob, pat):
    out = []
    s = 0
    while True:
        i = blob.find(pat, s)
        if i < 0:
            break
        out.append(i)
        s = i + 4
    return out


def headers(ram):
    """all script-block headers found in RAM"""
    out = []
    m1 = struct.pack('<I', 0x10000201)
    m2 = struct.pack('<I', 0x10000002)
    s = 0
    while True:
        i = ram.find(m1, s)
        if i < 0:
            break
        s = i + 1
        if ram[i + 4:i + 8] != m2:
            continue
        size = struct.unpack('<I', ram[i + 8:i + 12])[0]
        c10 = struct.unpack('<I', ram[i + 16:i + 20])[0]
        if c10 * 2 <= size <= 0xC0000 and 512 < c10 < 0x40000 and not (size & 1):
            out.append((i, size, c10))
    return out


PAT195 = struct.pack('<HH', 0x0034, 195)
PAT214 = struct.pack('<HH', 0x0034, 214)

for name, tag in STATES:
    ram = extract_ram(os.path.join(STATE, name))
    h195 = find_all(ram, PAT195)
    h214 = find_all(ram, PAT214)
    hs = headers(ram)
    print('%-24s (%s) CALL195=%d CALL214=%d headers=%s'
          % (name, tag, len(h195), len(h214),
             ['0x%X:size=%d,c10=%d' % h for h in hs]))
    cl195 = collections.Counter(x >> 16 for x in h195)
    cl214 = collections.Counter(x >> 16 for x in h214)
    if h195 or h214:
        print('    195 clusters:', {('0x%X000' % k): v for k, v in sorted(cl195.items())})
        print('    214 clusters:', {('0x%X000' % k): v for k, v in sorted(cl214.items())})
    # assign clusters to nearest preceding header
    for label, hits in (('195', h195), ('214', h214)):
        assign = collections.Counter()
        for x in hits:
            cands = [h for h in hs if h[0] <= x < h[0] + h[1]]
            if cands:
                assign['0x%X(c10=%d)' % (cands[0][0], cands[0][2])] += 1
            else:
                assign['NO_HEADER'] += 1
        if hits:
            print('    %s -> %s' % (label, dict(assign)))
    del ram
print('DONE', flush=True)
