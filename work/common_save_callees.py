# -*- coding: utf-8 -*-
"""Rank the save subsystem's callees as candidates for the DATA.BIN cipher.

With the lui+addiu sign bug fixed, string xref resolves the whole save
subsystem. All three file variants must be encrypted the same way:

    0x1461B4 SaveLoadGame    SaveLoadGame    + DATA.BIN
    0x146604 SaveLoadSystem  SaveLoadSystem  + DATA.BIN
    0x146844 SaveLoadSuspend SaveLoadSuspend + DATA.BIN

plus the DATA.BIN / SAVELOAD_PAC helpers
    0x14369C 0x1439C8 0x143B54 0x1470B0 0x143734
    0x142910 0x1434A4 0x14441C 0x132C8C 0x1414D4

So the cipher is very likely a callee shared by the three SaveLoad*
routines (or shared by the helpers). Steps:

  1. report the callees common to GAME / SYSTEM / SUSPEND
  2. score every save-subsystem callee for "looks like a transform":
       loops containing XOR/rotate  (strongest - a block/stream cipher loop)
       any XOR or rotate
       backwards branches
       few callers (a real crypto fn is called only by the save code,
       unlike memset/strcpy/log which have hundreds of callers)
  3. fully disassemble the top candidates so the loop body can be read

XOR/rotate are flagged rather than shifts, because sll/srl are everywhere in
ordinary code and would drown the signal.
"""
import array
import struct
import bisect
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

# ---- function boundaries ------------------------------------------------
words = array.array('I')
words.frombytes(code[:len(code) // 4 * 4])
PRO = [i * 4 for i, x in enumerate(words)
       if (x >> 16) == 0x27BD and (x & 0x8000)]
PRO.sort()


def extent(a):
    i = bisect.bisect_right(PRO, a + 8)
    return (PRO[i] if i < len(PRO) else len(code))


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
ARITH = {'mult', 'multu', 'div', 'divu'}

INFO = {}


def analyse(a):
    if a in INFO:
        return INFO[a]
    insns = list(md.disasm(code[a:extent(a)], a))
    jals, xors, arith, edges = [], [], [], []
    for n, i in enumerate(insns):
        if i.mnemonic == 'jal':
            jals.append((i.address, int(i.op_str, 0)))
        elif i.mnemonic in CRYPTO:
            xors.append((i.address, i.mnemonic, i.op_str))
        elif i.mnemonic in ARITH:
            arith.append((i.address, i.mnemonic, i.op_str))
        elif i.mnemonic[:1] == 'b' or i.mnemonic in ('j',):
            try:
                tgt = int(i.op_str.split(',')[-1], 0)
            except Exception:
                tgt = None
            if tgt is not None and tgt <= i.address:
                edges.append((i.address, i.mnemonic, tgt))
    # xor inside a loop body?
    loop_xor = [x for x in xors
                if any(t <= x[0] <= a0 for a0, _, t in edges)]
    r = INFO[a] = dict(start=a, n=len(insns), jals=jals, xors=xors,
                       arith=arith, edges=edges, loop_xor=loop_xor,
                       ncall=len(callers(a)))
    return r


LOADERS = {'GAME': 0x1461B4, 'SYSTEM': 0x146604, 'SUSPEND': 0x146844}
HELPERS = {0x14369C, 0x1439C8, 0x143B54, 0x1470B0, 0x143734,
           0x142910, 0x1434A4, 0x14441C, 0x132C8C, 0x1414D4}

print('=== save subsystem function sizes ===')
for nm, a in sorted(LOADERS.items(), key=lambda kv: kv[1]):
    r = analyse(a)
    print('  %-8s 0x%06X  insns=%-4d callers=%-3d jals=%d xor=%d backedges=%d'
          % (nm, a, r['n'], r['ncall'], len(r['jals']),
             len(r['xors']), len(r['edges'])))

sets = {}
for nm, a in LOADERS.items():
    sets[nm] = {t for _, t in analyse(a)['jals']}
common_all = sets['GAME'] & sets['SYSTEM'] & sets['SUSPEND']
print('\n=== callees used by ALL THREE SaveLoad* routines (%d) ==='
      % len(common_all))
for t in sorted(common_all):
    r = analyse(t)
    print('  0x%06X  callers=%-4d insns=%-4d xor=%-3d loopxor=%d backedges=%d'
          % (t, r['ncall'], r['n'], len(r['xors']),
             len(r['loop_xor']), len(r['edges'])))

# ---- candidate scoring --------------------------------------------------
cand = set(common_all) | set(HELPERS)
for nm, a in LOADERS.items():
    for _, t in analyse(a)['jals']:
        cand.add(t)
for h in list(HELPERS):
    if h in PRO or True:
        for _, t in analyse(h)['jals']:
            cand.add(t)

scored = []
for t in cand:
    r = analyse(t)
    s = 0
    if r['loop_xor']:
        s += 6
    if r['xors']:
        s += 3
    if r['edges']:
        s += 1
    if r['ncall'] <= 8:
        s += 3
    elif r['ncall'] <= 30:
        s += 1
    if r['ncall'] > 100:
        s -= 6          # shared utility (memset/strcpy/log)
    if r['n'] < 6:
        s -= 3          # trivial wrapper
    scored.append((s, t, r))

scored.sort(key=lambda x: (-x[0], x[1]))
print('\n=== top candidates (loops+xor, few callers) ===')
for s, t, r in scored[:18]:
    tag = ''
    if r['loop_xor']:
        tag = '  <== XOR INSIDE LOOP'
    print('  score=%2d  0x%06X  callers=%-4d insns=%-4d xor=%-3d '
          'loopxor=%d back=%d%s'
          % (s, t, r['ncall'], r['n'], len(r['xors']),
             len(r['loop_xor']), len(r['edges']), tag))

print('\n=== full dumps of strongest candidates ===')
shown = 0
for s, t, r in scored:
    if shown >= 3:
        break
    if not (r['xors'] and r['edges'] and r['n'] <= 0x500):
        continue
    shown += 1
    print('\n' + '-' * 70)
    print('--- 0x%06X  callers=%d insns=%d xor=%d ---'
          % (t, r['ncall'], r['n'], len(r['xors'])))
    print('-' * 70)
    for i in md.disasm(code[t:extent(t)], t):
        mark = ''
        if i.mnemonic == 'jal':
            mark = '  ; jal 0x%X (%d c)' % (int(i.op_str, 0),
                                            len(callers(int(i.op_str, 0))))
        elif i.mnemonic in CRYPTO:
            mark = '  ; <XOR>'
        print('0x%X: %-8s %-24s%s' % (i.address, i.mnemonic, i.op_str, mark))
print('DONE')
