import struct
PUSH_FETCH = {0,1,2,3,5,7,8}
def width(op, f1):
    if op == 50:
        return 1 if f1 in PUSH_FETCH else 0
    if op in (52,53,55,56,57,58):
        return 1
    return 0

def walk(units):
    """recursive descent. returns dict unit->(op,f1,f2,operand or None) for reachable code"""
    reach = {}
    work = [12]
    while work:
        i = work.pop()
        if i in reach or i < 0 or i >= len(units):
            continue
        u = units[i]; op, f1, f2 = u & 0x3F, (u>>6) & 0x3F, (u>>12) & 0xF
        w = width(op, f1)
        operand = units[i+1] if w and i+1 < len(units) else None
        reach[i] = (op, f1, f2, operand)
        nxt = i + 1 + w
        if op == 55 and operand is not None:
            t = (f2 << 16) | operand
            work.append(t)  # jump only
        elif op in (56, 57) and operand is not None:
            t = (f2 << 16) | operand
            work.append(t)
            work.append(nxt)
        elif op == 54:
            pass  # ENTER leaves the stream (dynamic cursor); no fallthrough
        else:
            work.append(nxt)
    return reach

def seq(reach):
    return sorted(reach.items())

if __name__ == '__main__':
    import sys
    tag = sys.argv[1] if len(sys.argv) > 1 else 'jp'
    if tag == 'jp':
        ram = open('D:/Documents/Default Project/work/psp_ram_jp.bin','rb').read()
        base = 0x08D2D000-0x08000000; size = 180224
    else:
        ram = open('D:/Documents/Default Project/work/psp_ram_usa3.bin','rb').read()
        base = 0x08D68000-0x08000000; size = 158152
    blk = ram[base+16:base+size]
    units = struct.unpack('<%dH' % (len(blk)//2), blk)
    r = walk(units)
    print(tag, 'units', len(units), 'reachable', len(r))
    import collections
    c = collections.Counter(v[0] for v in r.values())
    print('op histogram:', dict(sorted(c.items())))
    nulls = sorted(i for i,v in r.items() if v[0] in range(23,48) or v[0] in range(59,63))
    print('reachable NULL ops:', len(nulls), nulls[:30])
