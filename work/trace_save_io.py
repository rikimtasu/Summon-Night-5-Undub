# -*- coding: utf-8 -*-
"""Static trace of the save I/O path in the EBOOT.

The RAM-window approach is abandoned: three passes over save states found no
raw ciphertext and no parsed struct, so the buffer is read, transformed and
freed too quickly to catch. Everything here is static.

The chain we want:

    path format string  ->  path builder  ->  sceIoOpen/sceIoRead  ->  ?
                                                                      ^
                                                              the transform

DATA.BIN has no direct code reference (its address is assembled at runtime),
but the FORMAT STRING it is assembled from does have a static address:
    fva 0x21DCD8 = 'ms0:/PSP/SAVEDATA/%s%s/%s'
and the subsystem tag does too:
    fva 0x213CCA = 'comSvSaveLoad'
So: locate every instruction that materialises one of those fvas (lui + ori/addiu
within a short window), take the enclosing function, and dump it. Separately
enumerate the 15 callers of SavedataRun (0x92B0), the savedata hub already
identified, since one of them must own the load path.

Address discipline: strings are found as FILE offsets, fva = file_offset - SEG
with SEG = 0xC0, and code materialises fva (runtime = fva + 0x08804000).
Mixing the two produced a false pointer match earlier.
"""
import re
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
SAVEDATA_RUN = 0x92B0

d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

# ---- index every printable string by fva ---------------------------------
by_fva = {}
for m in re.finditer(rb'[\x20-\x7e]{5,}', d):
    by_fva[m.start() - SEG] = m.group()

# save-related anchors
ANCHORS = (b'ms0:/PSP/SAVEDATA', b'comSvSaveLoad', b'SaveLoad.cpp',
           b'SAVEDATA_PAC', b'SAVELOAD_PAC', b's_pLoadGameData',
           b'SavedataMount', b'SavedataUmount', b'SavedataRun')
want = {fva: s for fva, s in by_fva.items()
        if any(s.startswith(a) for a in ANCHORS)}
print('=== anchor strings (as fva) ===')
for fva, s in sorted(want.items()):
    print('  0x%06X  %r' % (fva, s[:64]))


def fn_start(a, back=0x800):
    """Walk back to the nearest function prologue: addiu $sp,$sp,-N (sign-bit)."""
    for t in range(a, max(0, a - back), -4):
        w = struct.unpack_from('<I', code, t)[0]
        if (w >> 16) == 0x27BD and (w & 0x8000):
            return t
    return a


def callers(target):
    enc = struct.pack('<I', 0x0C000000 | (target >> 2))
    out, s = [], 0
    while True:
        i = code.find(enc, s)
        if i < 0:
            break
        if i % 4 == 0:
            out.append(i)
        s = i + 1
    return out


# ---- find code that materialises an anchor fva ---------------------------
insns = list(md.disasm(code, 0))
lui_at = {}
hits = []
for n, ins in enumerate(insns):
    if ins.mnemonic == 'lui':
        r, v = [x.strip() for x in ins.op_str.split(',')]
        lui_at[r] = (n, int(v, 0))
    elif ins.mnemonic in ('ori', 'addiu'):
        p = [x.strip() for x in ins.op_str.split(',')]
        if len(p) != 3 or p[1] not in lui_at:
            continue
        li, hi = lui_at[p[1]]
        if n - li > 8:          # the lui must be the pair-partner, not stale
            continue
        imm = int(p[2], 0)
        if imm & 0x8000:
            imm -= 0x10000
        full = ((hi << 16) + imm) & 0xFFFFFFFF
        if full in want:
            hits.append((ins.address, full, ins.mnemonic))

print('\n=== code materialising an anchor string ===')
seen_fn = {}
for a, fva, mn in hits:
    st = fn_start(a)
    seen_fn.setdefault(st, []).append((a, fva, mn))
    print('  0x%06X %s -> 0x%06X  %r   [fn 0x%06X, %d callers]'
          % (a, mn, fva, want[fva][:40], st, len(callers(st))))

# ---- the 15 callers of SavedataRun --------------------------------------
print('\n=== callers of SavedataRun 0x%X ===' % SAVEDATA_RUN)
cr = callers(SAVEDATA_RUN)
print('  %d found' % len(cr))
for c in cr:
    print('    0x%06X   (fn 0x%06X, %d callers)'
          % (c, fn_start(c), len(callers(fn_start(c)))))

print('\n=== distinct enclosing functions ===')
allfn = sorted(set(list(seen_fn) + [fn_start(c) for c in cr]))
for f in allfn:
    print('  fn 0x%06X   callers=%d' % (f, len(callers(f))))
print('DONE')
