"""Locate the script-block header writer in the EBOOT.

The block header is:
  u32@+0 = 0x10000201, u32@+4 = 0x10000002, u32@+8 = size, u32@+16 = c10
Earlier scan missed it because 0x10000201 is normally built as
  lui  reg, 0x1000 ; ori/addiu reg2, $zero, 0x201
whose source register is $zero, not the lui target. Also look for
  lui reg, 0x1000 ; ori/addiu x, $zero, 0x202
and for code storing size/c10 at +0x08/+0x10 right after a file read.
"""
import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

ROOT = r'D:\Documents\Default Project'
d = open(ROOT + r'\EBOOT_USA_decrypted.bin', 'rb').read()
SEG, CODE_LEN = 0xC0, 0x242C94
code = d[SEG:SEG + CODE_LEN]
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False
insns = list(md.disasm(code, 0))
print('insns:', len(insns))

recent = []           # (idx, addr, reg, hi)
hits201 = []
hits202 = []
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'lui':
        r, v = ins.op_str.split(',')
        recent.append((idx, ins.address, r.strip(), int(v.strip(), 0)))
        if len(recent) > 12:
            recent.pop(0)
        continue
    if ins.mnemonic in ('ori', 'addiu'):
        p = [x.strip() for x in ins.op_str.split(',')]
        if len(p) != 3:
            continue
        imm = int(p[2], 0)
        if imm & 0x8000:
            imm -= 0x10000
        if imm in (0x201, 0x202):
            for (li, la, r, hi) in recent:
                if hi == 0x1000 and idx - li <= 10:
                    (hits201 if imm == 0x201 else hits202).append(
                        (la, ins.address, p[0], p[1], imm))

print('materializations of 0x10000201: %d' % len(hits201))
for h in hits201[:20]:
    print('   lui@0x%X  use@0x%X  %s,%s imm=0x%X' % h)
print('materializations of 0x10000002: %d' % len(hits202))
for h in hits202[:10]:
    print('   lui@0x%X  use@0x%X  %s,%s imm=0x%X' % h)

# also: any store of 0x201 / 0x10000201 via li+ori combos already covered.
# Dump context around the best candidates.
ctx_count = 0
for h in hits201[:6]:
    lo = max(0, h[1] - 0x60)
    print('\n--- context around 0x%X ---' % h[1])
    for ins in md.disasm(code[lo:h[1] + 0x60], lo):
        mark = '  <<<' if ins.address in (h[0], h[1]) else ''
        print('   0x%X: %s %s%s' % (ins.address, ins.mnemonic, ins.op_str, mark))
    ctx_count += 1
    if ctx_count >= 3:
        break
print('DONE', flush=True)
