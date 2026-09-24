# -*- coding: utf-8 -*-
"""Decide how this binary dispatches imported calls: jal-to-stub, or jalr.

The previous experiment assumed imports are reached by `jal` to a stub and
classified every non-function jal target as a stub. Result: 964 targets spread
over 0x20C..0x1D5E7C with no clustering whatsoever - i.e. they are just leaf
and tail-called functions my prologue heuristic did not recognise. Hypothesis
rejected.

MIPS convention offers the other mechanism: indirect calls via $t9, where the
callee address is materialised first (lui/addiu, or lw from a pointer table)
and then `jalr $t9`. If imports work that way, then for each jalr the few
instructions immediately BEFORE it will build the target, and targets that
land in an import-pointer table are the imported functions.

So: enumerate every jalr, walk back up to 8 instructions, and classify how the
target register was formed. Report counts by form. If a form yields targets
inside a narrow table region, that table is the import vector and its indices
map to the NIDs we already located at fva 0x211C94..0x211FBC.

Also dump all 3 program headers, which were filtered out of the earlier ELF
pass and may name the module-info/import segments directly.
"""
import struct
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()
code = d[SEG:SEG + 0x21121C]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False

# ---- program headers (all of them) --------------------------------------
(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
 e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
    '<HHIIIIIHHHHHH', d, 16)
PT = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR',
      0x70000000: 'PSPPREVIEW', 0x70000001: 'PSPMODULEINFO',
      0x70000002: 'PSPLIBRARYATTR', 0x70000003: 'PSPMODULEINFO2'}
print('=== program headers (%d) ===' % e_phnum)
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, off, va, pa, fs, ms, fl, al = struct.unpack_from('<IIIIIIII', d, o)
    print('  ph[%d] type=0x%08X (%s) off=0x%08X vaddr=0x%08X filesz=0x%X '
          'memsz=0x%X flags=0x%X'
          % (i, t, PT.get(t, '?'), off, va, fs, ms, fl))

# ---- how are call targets formed? ---------------------------------------
insns = list(md.disasm(code, 0))
print('\ntotal instructions: %d' % len(insns))

jalr = [n for n, i in enumerate(insns) if i.mnemonic == 'jalr']
print('jalr count: %d' % len(jalr))
jal = [n for n, i in enumerate(insns) if i.mnemonic == 'jal']
print('jal  count: %d' % len(jal))

forms = Counter()
t9_targets = Counter()
samples = defaultdict(list)
for n in jalr:
    reg = insns[n].op_str.split(',')[0].strip()
    form, tgt = 'unresolved', None
    # look back for lui/addiu or lw building $reg
    hi = None
    for k in range(n - 1, max(-1, n - 9), -1):
        ins = insns[k]
        ops = [x.strip() for x in ins.op_str.split(',')]
        if ins.mnemonic == 'lui' and ops[0] == reg:
            hi = int(ops[1], 0)
            # find the paired ori/addiu
            for m in range(k + 1, min(k + 6, n + 1)):
                o2 = insns[m]
                p2 = [x.strip() for x in o2.op_str.split(',')]
                if (o2.mnemonic in ('ori', 'addiu') and len(p2) == 3
                        and p2[1] == reg):
                    imm = int(p2[2], 0)
                    if o2.mnemonic == 'addiu' and imm & 0x8000:
                        imm -= 0x10000
                    tgt = ((hi << 16) + imm) & 0xFFFFFFFF
                    form = 'lui+addiu/ori'
                    break
            if tgt:
                break
        if ins.mnemonic == 'lw' and len(ops) == 2 and ops[1].endswith(')'):
            form = 'lw (indirect/table)'
            break
        if ins.mnemonic in ('addu', 'addiu', 'or') and len(ops) == 3 and ops[1] == reg:
            form = 'computed'
            break
    forms[form] += 1
    if tgt is not None:
        t9_targets[tgt] += 1
        if len(samples[form]) < 6:
            samples[form].append((insns[n].address, reg, tgt))

print('\n=== jalr target-formation forms ===')
for f, c in forms.most_common():
    print('  %-24s %d' % (f, c))

if t9_targets:
    print('\n=== jalr targets resolved via lui+addiu (%d distinct) ==='
          % len(t9_targets))
    for a, reg, t in samples.get('lui+addiu/ori', []):
        print('  0x%06X: jalr %s -> 0x%06X' % (a, reg, t))
    ts = sorted(t9_targets)
    print('  span 0x%06X .. 0x%06X' % (ts[0], ts[-1]))
    # cluster
    gaps = sorted(((ts[i + 1] - ts[i], ts[i], ts[i + 1])
                   for i in range(len(ts) - 1)), reverse=True)
    print('  largest gaps:')
    for g, x, y in gaps[:6]:
        print('    0x%X  0x%06X -> 0x%06X' % (g, x, y))

print('\n=== samples for other forms ===')
for f in ('lw (indirect/table)', 'computed', 'unresolved'):
    for a, reg, t in samples.get(f, [])[:4]:
        print('  %-22s 0x%06X: jalr %s -> 0x%06X' % (f, a, reg, t))
print('DONE')
