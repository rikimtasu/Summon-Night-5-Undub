# -*- coding: utf-8 -*-
"""Find the CALLERS of the three SaveLoad* functions and inspect them.

The callee-side is now closed: SaveLoadGame/SaveLoadSystem/SaveLoadSuspend and
everything they call contain no cipher loop, and the EBOOT save path has no
xor-based transform. One place the transform could still hide is the CALLER
layer - i.e. the code that marshals the in-memory state into the buffer before
SaveLoad*, or unpacks it after.

So enumerate callers of
    0x1461B4 SaveLoadGame     (2 callers)
    0x146604 SaveLoadSystem   (3 callers)
    0x146844 SaveLoadSuspend  (2 callers)
and for each enclosing function report size, caller count, xor/rotate count,
back-edges and whether a loop body contains an xor. Anything that loops with
an xor and has few callers is the candidate.

Also dump the SAVELOAD_PAC consumers not yet read (0x1439C8, 0x143B54) since
those sit inside the same 0x143xxx cluster as the DATA.BIN readers.
"""
import array
import struct
import bisect
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

words = array.array('I')
words.frombytes(code[:len(code) // 4 * 4])
PRO = sorted(i * 4 for i, x in enumerate(words)
             if (x >> 16) == 0x27BD and (x & 0x8000))


def extent(a):
    i = bisect.bisect_right(PRO, a + 8)
    return PRO[i] if i < len(PRO) else len(code)


def callers(t):
    enc = struct.pack('<I', 0x0C000000 | (t >> 2))
    out, s = [], 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


CRYPTO = {'xor', 'xori', 'rotr', 'rotl', 'wsbh'}
INFO = {}


def analyse(a):
    if a in INFO:
        return INFO[a]
    insns = list(md.disasm(code[a:extent(a)], a))
    xors, edges, jals = [], [], []
    for i in insns:
        if i.mnemonic in CRYPTO:
            xors.append((i.address, i.mnemonic, i.op_str))
        elif i.mnemonic == 'jal':
            jals.append(int(i.op_str, 0))
        elif i.mnemonic[:1] == 'b' or i.mnemonic == 'j':
            try:
                t = int(i.op_str.split(',')[-1], 0)
            except Exception:
                t = None
            if t is not None and t <= i.address:
                edges.append((i.address, t))
    loop_xor = [x for x in xors if any(lo <= x[0] <= hi for hi, lo in edges)]
    INFO[a] = dict(n=len(insns), xors=xors, edges=edges, jals=jals,
                   loop_xor=loop_xor, ncall=len(callers(a)))
    return INFO[a]


TARGETS = {'SaveLoadGame': 0x1461B4, 'SaveLoadSystem': 0x146604,
           'SaveLoadSuspend': 0x146844}

parents = {}
for nm, t in TARGETS.items():
    cs = callers(t)
    print('=== %s 0x%06X -> %d caller(s): %s'
          % (nm, t, len(cs), ', '.join('0x%X' % c for c in cs)))
    for c in cs:
        st = None
        for p in reversed(PRO):
            if p <= c:
                st = p
                break
        parents.setdefault(st, set()).add(nm)

print('\n=== enclosing functions, scored ===')
rows = []
for st in sorted(parents):
    r = analyse(st)
    s = 0
    if r['loop_xor']:
        s += 6
    if r['xors']:
        s += 3
    if r['edges']:
        s += 1
    if r['ncall'] <= 8:
        s += 3
    if r['ncall'] > 100:
        s -= 6
    rows.append((s, st, r))
rows.sort(key=lambda x: (-x[0], x[1]))
for s, st, r in rows:
    tag = '   <== XOR IN LOOP' if r['loop_xor'] else ''
    print('  score=%2d  fn 0x%06X  callers=%-4d insns=%-4d xor=%-2d '
          'back=%-2d serves=%s%s'
          % (s, st, r['ncall'], r['n'], len(r['xors']), len(r['edges']),
             ','.join(sorted(parents[st])), tag))

# also the two unread SAVELOAD_PAC consumers
print('\n=== unread SAVELOAD_PAC consumers ===')
for t in (0x1439C8, 0x143B54):
    r = analyse(t)
    print('  0x%06X callers=%d insns=%d xor=%d back=%d'
          % (t, r['ncall'], r['n'], len(r['xors']), len(r['edges'])))

# dump the best parent if any has xor
best = [x for x in rows if x[0] >= 4]
if best:
    s, st, r = best[0]
    print('\n' + '=' * 70)
    print('--- dump 0x%06X (score %d) callers=%d ---' % (st, s, r['ncall']))
    print('=' * 70)
    for i in list(md.disasm(code[st:extent(st)], st))[:220]:
        mark = ''
        if i.mnemonic == 'jal':
            ct = int(i.op_str, 0)
            mark = '  ; jal 0x%X (%d c)' % (ct, len(callers(ct)))
        elif i.mnemonic in CRYPTO:
            mark = '  ; <XOR>'
        print('0x%X: %-8s %-24s%s' % (i.address, i.mnemonic, i.op_str, mark))
print('DONE')
