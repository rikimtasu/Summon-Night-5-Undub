"""Per-block voice-function resolution and voice-site census.

Key finding: op52 f1=1 targets are per-block function IDs (prologue uses
195=text, 214=voice; other blocks use different ids), so byte-pattern search
for 195/214 only works for the prologue. The voice call is instead
recognizable structurally: an argument push (op50 f1=10 const / f1=11 f2-1 /
f1=4 pair) immediately followed by an op52 f1=1 call. In the known prologue
this yields exactly the known voice sites with target 214, which calibrates
the detector. Apply it to every resident block.
"""
import struct, sys, os, collections
import zstandard
sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

STATE = r'D:\Video_Game\Emulator\PSP\PPSSPP 1.20\ppsspp\memstick\PSP\PPSSPP_STATE'
STATES = [
    ('ULUS10656_1.01_0.ppst', 'usa'),
    ('ULUS10656_1.01_3.ppst', 'usa'),
    ('NPJH50696_1.01_0.ppst', 'jp'),
    ('NPJH50696_1.01_4.ppst', 'jp'),
]
M1 = struct.pack('<I', 0x10000201)
M2 = struct.pack('<I', 0x10000002)


def extract_ram(path):
    d = open(path, 'rb').read()
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory'
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


def headers(ram):
    out = []
    s = 0
    while True:
        i = ram.find(M1, s)
        if i < 0:
            break
        s = i + 1
        if ram[i + 4:i + 8] != M2:
            continue
        size = struct.unpack('<I', ram[i + 8:i + 12])[0]
        c10 = struct.unpack('<I', ram[i + 16:i + 20])[0]
        if size & 1 or not (c10 * 2 <= size <= 0x600000 and 64 < c10 < 0x100000):
            continue
        out.append((i, size, c10))
    return out


def arg_form(push_tok):
    """classify an op50 push as a voice-arg candidate; return (kind, value)"""
    op, f1, f2, ops = push_tok[1], push_tok[2], push_tok[3], push_tok[4]
    if op != 50:
        return None
    if f1 == 10 and ops:
        return ('const', ops[0])
    if f1 == 11:
        return ('f2', f2 - 1)
    if f1 == 4 and ops:
        return ('pair', ops[0])
    return None


def analyze(ram, base, size, c10, label):
    tok = disasm(ram[base:base + c10 * 2], 12)
    if not tok or not (c10 - 4 <= tok[-1][0] + 1 <= c10):
        print('   [%s] LANDING FAIL (last=%s c10=%d)' % (label, tok[-1][0] if tok else None, c10))
        return
    # push -> immediate call pairs
    target_hist = collections.Counter()
    sites = collections.defaultdict(list)   # target -> [(unit, kind, val)]
    for k in range(1, len(tok)):
        t = tok[k]
        if t[1] == 52 and t[2] == 1 and t[4]:
            form = arg_form(tok[k - 1])
            if form:
                target_hist[t[4][0]] += 1
                sites[t[4][0]].append((t[0], form[0], form[1]))
    print('   [%s] tokens=%d  push->call targets: %s'
          % (label, len(tok), dict(target_hist.most_common(8))))
    return sites, tok


print('=== per-block push->call calibration and census ===')
for name, tag in STATES:
    ram = extract_ram(os.path.join(STATE, name))
    print('%s (%s)' % (name, tag))
    for (o, size, c10) in headers(ram):
        r = analyze(ram, o, size, c10, 'base=0x%X c10=%d' % (o, c10))
        if not r:
            continue
        sites, tok = r
        for tgt, lst in sorted(sites.items(), key=lambda kv: -len(kv[1]))[:4]:
            kinds = collections.Counter(k for _, k, _ in lst)
            vals = [v for _, _, v in lst]
            vmin, vmax = min(vals), max(vals)
            print('      target %-6d n=%-5d kinds=%s vid_range=%d..%d first_units=%s'
                  % (tgt, len(lst), dict(kinds), vmin, vmax,
                     [u for u, _, _ in lst[:6]]))
    del ram
print('DONE', flush=True)
