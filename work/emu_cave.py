"""Emulate the v3 cave against real USA RAM + patched EBOOT bytes to find the fault."""
import struct

SEG = 0xC0
RT = 0x08804000

ram = open(r'D:\Documents\Default Project\work\psp_ram_usa3.bin', 'rb').read()
RAM_BASE = 0x08000000
eboot = open(r'D:\Documents\Default Project\work\EBOOT_USA_patched.bin', 'rb').read()

mem = {}


def w32(a, v):
    mem[a] = v & 0xFFFFFFFF


def r32(a):
    if a in mem:
        return mem[a]
    o = a - RAM_BASE
    if 0 <= o + 4 <= len(ram):
        return struct.unpack('<I', ram[o:o + 4])[0]
    raise Exception('unmapped read %08x' % a)


# overlay ONLY patched regions (cave+table, hook site); everything else = live RAM
for fva in range(0x236378, 0x236378 + 4184, 4):
    w32(RT + fva, struct.unpack('<I', eboot[SEG + fva:SEG + fva + 4])[0])
for fva in (0x1784C, 0x17850):
    w32(RT + fva, struct.unpack('<I', eboot[SEG + fva:SEG + fva + 4])[0])

# USA engine base from runtime text-handler prologue (patched lui)
lw = r32(0x0881B768)
assert (lw >> 26) == 0x0F, hex(lw)
page = (lw & 0xFFFF) << 16
lw2 = r32(0x0881B76C)
off = lw2 & 0xFFFF
glo = r32(page + off)
eng = (glo + 0x6DA0) & 0xFFFFFFFF
print('global page %08x ptr %08x engine %08x' % (page, glo, eng))
print('voiceobj *(eng+0x30) = %08x' % r32(eng + 0x30))

# synthetic stack slot with p0 = first-shop-line string address
ctx = 0x08ACFA14
stream = r32(ctx + 0x1C)
c10 = r32(ctx + 0x10)
print('ctx stream %08x c10 %s' % (stream, hex(c10)))
p0 = (stream + 2 * (c10 + 1)) & 0xFFFFFFFF  # USA stridx 1 = Welcome line
SP = 0x09F00000
w32(SP, p0)

regs = {'s0': ctx, 's2': eng, 'sp': SP, 'ra': 0x0881B858 + 0x1000}
for i in range(32):
    regs.setdefault(i, 0)
regs[16] = ctx
regs[18] = eng
regs[29] = SP
regs[31] = 0x0881B858 + 0x1000
RN = {'zero': 0, 'at': 1, 'v0': 2, 'v1': 3, 'a0': 4, 'a1': 5, 'a2': 6, 'a3': 7,
      't0': 8, 't1': 9, 't2': 10, 't3': 11, 't4': 12, 't5': 13, 't6': 14, 't7': 15,
      's0': 16, 's1': 17, 's2': 18, 's3': 19, 's4': 20, 's5': 21, 's6': 22, 's7': 23,
      't8': 24, 't9': 25, 'k0': 26, 'k1': 27, 'gp': 28, 'sp': 29, 'fp': 30, 'ra': 31}


def reg(n):
    return 0 if n == 0 else regs[n]


def setreg(n, v):
    if n != 0:
        regs[n] = v & 0xFFFFFFFF


CAVE = 0x08A3A378
pc = CAVE
steps = 0
while steps < 5000:
    w = r32(pc)
    op = w >> 26
    if w == 0:
        pc += 4
    elif op == 0x23:  # lw
        setreg((w >> 16) & 31, r32((reg((w >> 21) & 31) + (w & 0xFFFF if w & 0x8000 == 0 else w & 0xFFFF - 0x10000)) & 0xFFFFFFFF))
        pc += 4
    elif op == 0x2B or (op == 0x00 and False):  # sw
        a = (reg((w >> 21) & 31) + (w & 0xFFFF if w & 0x8000 == 0 else w & 0xFFFF - 0x10000)) & 0xFFFFFFFF
        o = a - RAM_BASE
        print('STORE %08x <- %08x at pc %08x' % (a, reg((w >> 16) & 31), pc))
        pc += 4
    elif op == 0x00:
        fn = w & 63
        if fn == 0x25:  # or
            setreg((w >> 11) & 31, reg((w >> 21) & 31) | reg((w >> 16) & 31))
            pc += 4
        elif fn == 0x23:  # subu
            setreg((w >> 11) & 31, reg((w >> 21) & 31) - reg((w >> 16) & 31))
            pc += 4
        elif fn == 0x21:  # addu/move
            setreg((w >> 11) & 31, reg((w >> 21) & 31) + reg((w >> 16) & 31))
            pc += 4
        else:
            raise Exception('special %s at %08x' % (hex(fn), pc))
    elif op == 0x0F:  # lui
        setreg((w >> 16) & 31, (w & 0xFFFF) << 16)
        pc += 4
    elif op == 0x0D:  # ori
        setreg((w >> 16) & 31, reg((w >> 21) & 31) | (w & 0xFFFF))
        pc += 4
    elif op == 0x09:  # addiu
        imm = w & 0xFFFF
        imm -= 0x10000 if imm & 0x8000 else 0
        setreg((w >> 16) & 31, reg((w >> 21) & 31) + imm)
        pc += 4
    elif op == 0x05:  # bne
        imm = w & 0xFFFF
        imm -= 0x10000 if imm & 0x8000 else 0
        pc = (pc + 8 + imm * 4) & 0xFFFFFFFF if reg((w >> 21) & 31) != reg((w >> 16) & 31) else pc + 8
        steps += 1
        continue
    elif op == 0x02:  # j
        pc = (pc & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
        steps += 1
        continue
    elif op == 0x03:  # jal
        setreg(31, pc + 8)
        t = (pc & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
        print('JAL %08x from %08x (ra=%08x)' % (t, pc, pc + 8))
        break
    else:
        raise Exception('op %s at %08x word %08x' % (hex(op), pc, w))
    steps += 1

print('steps:', steps, 'final pc %08x' % pc)
print('t2 key=%s (expect %s)' % (hex(reg(10)), hex((p0 - stream) & 0xFFFFFFFF)))
