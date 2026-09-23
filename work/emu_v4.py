"""Emulate v4 split cave (descriptors + chunked table) vs real RAM + patched file."""
import struct

SEG = 0xC0
RT = 0x08804000
CODE = 0x08A28868

ram = open(r'D:\Documents\Default Project\work\psp_ram_usa3.bin', 'rb').read()
eboot = open(r'D:\Documents\Default Project\work\EBOOT_USA_patched.bin', 'rb').read()
mem = {}


def w32(a, v):
    mem[a] = v & 0xFFFFFFFF


def r32(a):
    if a in mem:
        return mem[a]
    o = a - 0x08000000
    if 0 <= o + 4 <= len(ram):
        return struct.unpack('<I', ram[o:o + 4])[0]
    raise Exception('unmapped %08x' % a)


# overlay ONLY v4 payload ranges from patched file
for fva in list(range(0x17848, 0x17850, 4)) + list(range(0x224868, 0x224868 + 228, 4)):
    w32(RT + fva, struct.unpack('<I', eboot[SEG + fva:SEG + fva + 4])[0])
for (fva, ln) in [(0x2334F4, 648), (0x22E33C, 496), (0x2242B8, 396), (0x22FEC0, 380),
                  (0x2240E4, 380), (0x223C40, 332), (0x22B760, 332), (0x22D164, 332),
                  (0x223E30, 304), (0x224F20, 288), (0x22F2F0, 228)]:
    for f in range(fva, fva + ln, 4):
        w32(RT + f, struct.unpack('<I', eboot[SEG + f:SEG + f + 4])[0])

# engine from runtime prologue
page = (r32(0x0881B768) & 0xFFFF) << 16
glo = r32(page + (r32(0x0881B76C) & 0xFFFF))
eng = (glo + 0x6DA0) & 0xFFFFFFFF
ctx = 0x08ACFA14
stream = r32(ctx + 0x1C)
c10 = r32(ctx + 0x10)
P0 = int(open(r'C:\Users\User\AppData\Local\Temp\opencode\p0.txt').read().strip(), 0) \
    if __import__('os').path.exists(r'C:\Users\User\AppData\Local\Temp\opencode\p0.txt') else None
if P0 is None:
    P0 = (stream + 2 * (c10 + 1)) & 0xFFFFFFFF  # MISS (first shop line)
SP = 0x09F00000
w32(SP, P0)
regs = [0] * 32
regs[16] = ctx
regs[18] = eng
regs[29] = SP


def sx(v):
    return v - 0x10000 if v & 0x8000 else v


pc = CODE
steps = 0
stores = []
while steps < 20000:
    w = r32(pc)
    op = w >> 26
    rs, rt, rd = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
    imm = sx(w & 0xFFFF)
    if w == 0:
        pc += 4
    elif op == 0x23:
        regs[rt] = r32((regs[rs] + imm) & 0xFFFFFFFF)
        pc += 4
    elif op == 0x2B:
        a = (regs[rs] + imm) & 0xFFFFFFFF
        stores.append((pc, a, regs[rt]))
        pc += 4
    elif op == 0x00:
        fn = w & 63
        if fn in (0x21, 0x25):
            regs[rd] = (regs[rs] + regs[rt]) & 0xFFFFFFFF if fn == 0x21 else (regs[rs] | regs[rt]) & 0xFFFFFFFF
            pc += 4
        elif fn == 0x23:
            regs[rd] = (regs[rs] - regs[rt]) & 0xFFFFFFFF
            pc += 4
        else:
            raise Exception('special %x at %08x' % (fn, pc))
    elif op == 0x0F:
        regs[rt] = (w & 0xFFFF) << 16
        pc += 4
    elif op in (0x0D, 0x09):
        regs[rt] = (regs[rs] | (w & 0xFFFF)) & 0xFFFFFFFF if op == 0x0D else (regs[rs] + imm) & 0xFFFFFFFF
        pc += 4
    elif op == 0x05:
        pc = (pc + 8 + imm * 4) & 0xFFFFFFFF if regs[rs] != regs[rt] else pc + 8
        steps += 1
        continue
    elif op == 0x02:
        pc = (pc & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
        steps += 1
        continue
    elif op == 0x03:
        regs[31] = pc + 8
        print('JAL %08x from %08x' % ((pc & 0xF0000000) | ((w & 0x3FFFFFF) << 2), pc))
        break
    else:
        raise Exception('op %x at %08x' % (op, pc))
    steps += 1
print('steps:', steps, 'stores:', [(hex(p), hex(a), hex(v)) for p, a, v in stores])
print('key t2=', hex(regs[10]))
