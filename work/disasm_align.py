import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

# Authoritative semantics from EBOOT JP opcode tables / handler disassembly:
# op50 push-dispatch (jump table 0x1FDF78, indexed by f1):
#   f1=0,1,2 : fetchS + vtable call(28/2C/30) -> push result      [+1]
#   f1=3     : push stack[count + fetchS]                          [+1]
#   f1=4     : push (fetchU2<<16)|fetchU1                          [+2]
#   f1=5     : push u16 @ stream + 2*(c10 + (f2<<16|fetchU))       [+1]  DATA LOOKUP
#   f1=6     : push (f2<<16)|fetchU                                [+1]
#   f1=7     : push c18                                            [+0]
#   f1=8     : push c14                                            [+0]
#   f1=9     : push c10                                            [+0]
#   f1=10    : push fetchS                                         [+1]
#   f1=11    : push (f2-1)                                         [+0]
# op52 = CALL: fetchU target; push [f1, retcursor, count, c18]; cursor=(f2<<16)|target   [+1]
# op53 = open frame: fetchU (dead pad); push [f1, count]; count=sp; flag38=0             [+1]
# op54 = RETURN: c18=pop, count=pop, cursor=pop, sp-=pop (4 pops)                        [+0]
# op55 = jump      : cursor = (f2<<16)|fetchU                       [+1]
# op56 = jump if TRUE  (pop != 0)                                   [+1]
# op57 = jump if FALSE (pop == 0)                                   [+1]
# op58 = stack[count+fetchS] = 0                                    [+1]
# op48: count = sp (old); sp += f1.  op49: sp -= f1.

def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v

def width(op, f1):
    if op == 50:
        if f1 == 4:
            return 2
        if f1 in (0, 1, 2, 3, 5, 6, 10):
            return 1
        return 0
    if op in (52, 53, 55, 56, 57):
        return 1
    if op == 58:
        return 1
    return 0

def decode_at(units, i):
    """returns token (cursor, op, f1, f2, operands) and next index"""
    u = units[i]
    op, f1, f2 = u & 0x3F, (u >> 6) & 0x3F, (u >> 12) & 0xF
    w = width(op, f1)
    ops = []
    if w and i + w <= len(units):
        if op == 50 and f1 == 4:
            ops = [units[i+1], units[i+2]]
        elif op == 50 and f1 in (0, 1, 2, 3, 10):
            ops = [s16(units[i+1])]
        else:
            ops = [units[i+1]]
    return (i, op, f1, f2, tuple(ops)), i + 1 + w

def disasm(blk_bytes, start_unit=0):
    units = struct.unpack('<%dH' % (len(blk_bytes)//2), blk_bytes)
    out = []
    i = start_unit
    while i < len(units):
        tok, i = decode_at(units, i)
        out.append(tok)
    return out

def tokens(dis):
    # compare on op shape, not raw cursor/target values
    return [(op, f1, f2, tuple('T' if isinstance(x, int) else x for x in ops)) for (_, op, f1, f2, ops) in dis]

if __name__ == '__main__':
    ram = open(os.path.join(paths.WORK, 'psp_ram_jp.bin'), 'rb').read()
    o = 0x08D2D000 - 0x08000000
    blk = ram[o:o+180224]
    d = disasm(blk, 12)
    for t in d[:40]:
        print(t)
