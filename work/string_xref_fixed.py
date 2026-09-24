# -*- coding: utf-8 -*-
"""Find string consumers with CORRECT lui+addiu immediate arithmetic.

The earlier consumer scans reported that 'ms0:/PSP/SAVEDATA/%s%s/%s',
'DATA.BIN', 's_pLoadGameData is NULL!' and 'SAVELOAD_PAC is not read!' had no
code references at all, and concluded the addresses must be register-derived.

That conclusion was wrong. Capstone prints MIPS immediates already signed for
addiu (it emits '-0x2328', not '0xdcd8'). The old code did:

    imm = int(tok, 0)          # -9000
    if imm & 0x8000:           # true for a negative Python int too!
        imm -= 0x10000         # -> -74536   WRONG, double subtraction

so every lui+addiu pair with a NEGATIVE offset resolved to garbage. The two
strings that did resolve (SavedataRun = +0x23A8, comSvSaveLoad = +0x3CCA) were
exactly the two with positive offsets; every miss needed a negative offset.

Fix: trust capstone's sign for addiu (signed, zero-extend only when it printed
a positive >= 0x8000), and always zero-extend for ori.

VALIDATION: this must reproduce the two known-good hits before anything new is
believed -
    0x009318 -> 0x2123A8 'SavedataRun'
    0x0207A0 -> 0x213CCA 'comSvSaveLoad'
then report every save-related string consumer, newly visible.
"""
import re
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

# ---- index save-related strings by fva -----------------------------------
PAT = (b'ms0:/PSP/SAVEDATA', b'comSvSaveLoad', b'SaveLoad.cpp', b'SavedataRun',
       b's_pLoadGameData', b'SAVELOAD_PAC', b'SAVEDATA_PAC', b'DATA.BIN',
       b'sceUtilitySavedata', b'SavedataMount', b'SavedataUmount',
       b'SavedataLoad', b'SavedataSave', b'PARAM.SFO', b'ICON0',
       b'SaveLoadGame', b'SaveLoadSystem', b'SaveLoadSuspend')
by_fva = {}
for m in re.finditer(rb'[\x20-\x7e]{5,}', d):
    s = m.group()
    if any(s.startswith(p) for p in PAT):
        by_fva[m.start() - SEG] = s

print('=== anchor strings (fva) ===')
for fva, s in sorted(by_fva.items()):
    print('  0x%06X  %r' % (fva, s[:70]))


def imm_of(tok, mnemonic):
    """Correct immediate: capstone already sign-extends addiu."""
    t = tok.strip()
    neg = t.startswith('-')
    v = int(t, 0)
    if mnemonic == 'ori':
        return v & 0xFFFF                  # zero-extend, always unsigned
    if neg:
        return v                           # already signed
    if v >= 0x8000:                        # addiu printed as large positive
        v -= 0x10000
    return v


def fn_start(a, back=0x800):
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


# ---- scan for materialisation -------------------------------------------
insns = list(md.disasm(code, 0))
lui_at = {}
hits = []
for n, ins in enumerate(insns):
    ops = [x.strip() for x in ins.op_str.split(',')]
    if ins.mnemonic == 'lui' and len(ops) == 2:
        lui_at[ops[0]] = (n, int(ops[1], 0))
    elif ins.mnemonic in ('ori', 'addiu') and len(ops) == 3:
        dst, base = ops[0], ops[1]
        if base not in lui_at:
            continue
        li, hi = lui_at[base]
        if n - li > 8:
            continue
        full = ((hi << 16) + imm_of(ops[2], ins.mnemonic)) & 0xFFFFFFFF
        if full in by_fva:
            hits.append((ins.address, full, ins.mnemonic, dst))

print('\n=== VALIDATION against known-good hits ===')
expect = {0x9318: 0x2123A8, 0x207A0: 0x213CCA}
found_map = {a: f for a, f, _, _ in hits}
ok = True
for ea, fva in expect.items():
    got = found_map.get(ea)
    status = 'OK' if got == fva else 'MISMATCH (got %s)' % (
        hex(got) if got else 'none')
    if got != fva:
        ok = False
    print('  0x%06X -> expect 0x%06X : %s' % (ea, fva, status))
if not ok:
    print('  !! validation failed, do not trust new results !!')

print('\n=== ALL consumers found (%d) ===' % len(hits))
seen = {}
for a, fva, mn, dst in sorted(hits):
    st = fn_start(a)
    seen.setdefault(st, []).append((a, fva))
    print('  0x%06X %-6s -> 0x%06X  %-26r [fn 0x%06X callers=%d]'
          % (a, mn, fva, by_fva[fva][:26], st, len(callers(st))))

print('\n=== distinct enclosing functions ===')
for st in sorted(seen):
    strs = sorted({by_fva[f][:30] for _, f in seen[st]})
    print('  fn 0x%06X callers=%-3d %s' % (st, len(callers(st)), strs))
print('DONE')
