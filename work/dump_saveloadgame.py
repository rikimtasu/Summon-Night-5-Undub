# -*- coding: utf-8 -*-
"""Disassemble SaveLoadGame (0x1461B4) and hunt the buffer transform.

With the immediate-arithmetic bug fixed, string xref now resolves the save
subsystem cleanly:

    0x1461B4  SaveLoadGame   + DATA.BIN + SAVELOAD_PAC   (2 callers)
    0x146604  SaveLoadSystem + DATA.BIN + SAVELOAD_PAC   (3 callers)
    0x146844  SaveLoadSuspend + DATA.BIN + SAVELOAD_PAC  (2 callers)
    0x132C8C  builds 'ms0:/PSP/SAVEDATA/%s%s/%s'
    0x1414D4  's_pLoadGameData is NULL!'

0x1461B4 is the game-save routine, so the decrypt lives in or beside it.

What we are looking for, given the cipher is strong and per-save:
  * a bounded loop over the buffer doing XOR with a register, plus shifts/rotates
  * or a call to a subroutine that does (a block cipher or a PRNG keystream)
  * the call to sceIoRead (corrected NID 0x6A638D83) to bound where read ends
  * a loop counter compared against 0x298A0 (170144) - though no such literal
    was found anywhere, so the size may come from sceIoLseek(SEEK_END)

Plan: print the whole function, list every jal with callee call-counts, and
flag every instruction doing xor/shift/rotate together with backward branches
(loop back-edges). Loop bodies are where the transform is.
"""
import struct
from collections import Counter
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x242C94]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False


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


def dump(fn, label, maxb=0x520):
    print('\n' + '=' * 78)
    print('=== fn 0x%06X  (%s)  callers=%d ==='
          % (fn, label, len(callers(fn))))
    print('=' * 78)
    insns = list(md.disasm(code[fn:fn + maxb], fn))
    # stop at next function prologue after the first 8 instructions
    end = len(insns)
    for n, i in enumerate(insns):
        if n > 8 and i.mnemonic == 'addiu' \
                and i.op_str.startswith('$sp, $sp, -'):
            end = n
            break
    insns = insns[:end]

    jals = []
    loops = []
    crypto = []
    for n, i in enumerate(insns):
        if i.mnemonic == 'jal':
            t = int(i.op_str, 0)
            jals.append((i.address, t))
        # backward branch = loop back-edge
        if i.mnemonic.startswith('b') or i.mnemonic in ('j',):
            try:
                tgt = int(i.op_str.split(',')[-1], 0)
            except Exception:
                tgt = None
            if tgt is not None and tgt <= i.address:
                loops.append((i.address, i.mnemonic, tgt))
        if i.mnemonic in ('xor', 'xori', 'sll', 'srl', 'sra', 'rotl', 'rotr',
                          'wsbh', 'wswl', 'wswr'):
            crypto.append((i.address, i.mnemonic, i.op_str))

    for n, i in enumerate(insns):
        mark = ''
        if i.mnemonic == 'jal':
            t = int(i.op_str, 0)
            mark = '   ; jal 0x%X  (callers=%d)' % (t, len(callers(t)))
        elif i.mnemonic in ('xor', 'xori', 'sll', 'srl', 'sra'):
            mark = '   ; <shift/xor>'
        print('0x%X: %-8s %-22s%s' % (i.address, i.mnemonic, i.op_str, mark))

    print('\n  --- summary for 0x%06X ---' % fn)
    print('  instructions      : %d' % len(insns))
    print('  jal targets       : %s'
          % ', '.join('0x%X(%d c)' % (t, len(callers(t))) for _, t in jals))
    print('  loop back-edges   : %d' % len(loops))
    for a, mn, tg in loops:
        print('      0x%X: %s -> 0x%X' % (a, mn, tg))
    print('  shift/xor insns   : %d' % len(crypto))
    for a, mn, op in crypto[:25]:
        print('      0x%X: %-5s %s' % (a, mn, op))
    if len(crypto) > 25:
        print('      ... %d more' % (len(crypto) - 25))


dump(0x1461B4, 'SaveLoadGame')
print('DONE')
