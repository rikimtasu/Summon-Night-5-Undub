import struct, sys

PUSH_FETCH = {0,1,2,3,5,7,8}
def width(op, f1):
    if op == 50:
        if f1 == 4: return 2
        return 1 if f1 in PUSH_FETCH else 0
    if op in (52,53,55,56,57,58):
        return 1
    return 0

def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v
def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v

class VM:
    def __init__(self, units):
        self.u = units
        self.cursor = 12
        self.stack = []
        self.sp = 0
        self.count = 0
        self.c10 = 0xA818; self.c14 = 0xFFFFFFFF; self.c18 = 1
        self.flag38 = 0
        self.steps = 0
        self.trace = []
    def fetchU(self):
        v = self.u[self.cursor]; self.cursor += 1
        return v
    def fetchS(self):
        return s16(self.fetchU())
    def push(self, v):
        v &= 0xFFFFFFFF
        if self.sp < len(self.stack): self.stack[self.sp] = v
        else: self.stack.append(v)
        self.sp += 1
    def pop(self):
        self.sp -= 1
        if self.sp < 0: raise Exception('stack underflow')
        return self.stack[self.sp]
    def push50(self, f1, f2):
        if f1 in (0,1,2): raise Exception(f'op50 helper f1={f1} stub')
        if f1 == 3: return self.stack[self.count + self.fetchS()]
        if f1 == 4:
            a = self.fetchU(); b = self.fetchU(); return (b << 16) | a
        if f1 == 5: return self.fetchS()
        if f1 == 6: return (f2 - 1) & 0xFFFFFFFF
        if f1 == 7: raise Exception('op50 lookup f1=7 stub')
        if f1 == 8: return ((f2 << 16) | self.fetchU()) & 0xFFFFFFFF
        if f1 == 9: return self.c18
        if f1 == 10: return self.c14
        if f1 == 11: return self.c10
        raise Exception(f'op50 bad f1={f1}')
    def step(self):
        u = self.u[self.cursor]; self.cursor += 1
        op, f1, f2 = u & 0x3F, (u >> 6) & 0x3F, (u >> 12) & 0xF
        w = width(op, f1)
        operand = self.u[self.cursor] if w else None
        if w: self.cursor += 0  # operands consumed lazily by op handlers via fetch
        # NOTE: widths advance cursor for skipped operands; fetch-ops advance as they read.
        # To keep it simple: handlers call fetchU/fetchS which advance; for skipped pad operand, advance here:
        if op in (52, 53) or (op == 50 and False):
            pass
        self.trace.append((self.cursor-1 if not w else self.cursor-1-w, op, f1, f2, operand))
        if op == 0: pass
        elif op == 1:
            b, a = self.pop(), self.pop(); self.push(a+b)
        elif op == 2:
            b, a = self.pop(), self.pop(); self.push(a-b)
        elif op == 3:
            b, a = self.pop(), self.pop(); self.push(a*b)
        elif op == 4:
            b, a = self.pop(), self.pop()
            a, b = s32(a), s32(b)
            self.push(int(a/b) if b != 0 else 0)
        elif op == 5:
            b, a = self.pop(), self.pop()
            a, b = s32(a), s32(b)
            self.push(a - int(a/b)*b if b != 0 else 0)
        elif op == 6:
            self.push(-self.pop())
        elif op == 7:
            b, a = self.pop(), self.pop(); self.push(a & b)
        elif op == 8:
            b, a = self.pop(), self.pop(); self.push(a | b)
        elif op == 9:
            b, a = self.pop(), self.pop(); self.push(a ^ b)
        elif op == 10:
            self.push(~self.pop())
        elif op == 11:
            self.push(1 if self.pop() == 0 else 0)
        elif op == 12:
            b, a = self.pop(), self.pop(); self.push(1 if (a ^ b) == 0 else 0)
        elif op == 13:
            b, a = self.pop(), self.pop(); self.push(1 if (a ^ b) != 0 else 0)
        elif op == 14:
            b, a = self.pop(), self.pop(); self.push(1 if s32(a) < s32(b) else 0)
        elif op == 15:
            b, a = self.pop(), self.pop(); self.push(1 if not (s32(b) < s32(a)) else 0)
        elif op == 16:
            b, a = self.pop(), self.pop(); self.push(1 if s32(b) < s32(a) else 0)
        elif op == 17:
            b, a = self.pop(), self.pop(); self.push(1 if not (s32(a) < s32(b)) else 0)
        elif op == 18:
            b, a = self.pop(), self.pop(); self.push(1 if (a != 0 and b != 0) else 0)
        elif op == 19:
            b, a = self.pop(), self.pop(); self.push(1 if (a != 0 or b != 0) else 0)
        elif op == 20:
            a = self.pop(); self.push(1 if (a ^ self.c18) == 0 else 0)
        elif op == 21:
            b, a = self.pop(), self.pop(); self.push((a << (b & 31)) & 0xFFFFFFFF)
        elif op == 22:
            b, a = self.pop(), self.pop(); self.push(s32(a) >> (b & 31))
        elif op in (15,17,18,19,20,21,22):
            raise Exception(f'op{op} stub at cursor {self.cursor-1}')
        elif op == 48:
            self.sp += f1; self.count = self.sp
        elif op == 49:
            self.sp -= f1
        elif op == 50:
            self.push(self.push50(f1, f2))
        elif op == 51:
            raise Exception(f'op51 indirect stub at cursor {self.cursor-1}')
        elif op == 52:
            self.fetchU()  # skipped pad
            self.push(f1); self.push(self.cursor); self.push(self.count); self.push(self.c18)
        elif op == 53:
            self.fetchU()  # skipped pad
            self.push(f1); self.push(self.count); self.count = self.sp; self.flag38 = 0
        elif op == 54:
            A, B, C, D = self.pop(), self.pop(), self.pop(), self.pop()
            self.c18, self.count, self.cursor = A, B, C
            self.sp -= s32(D)
        elif op == 55:
            self.cursor = (f2 << 16) | self.fetchU()
        elif op == 56:
            t = (f2 << 16) | self.fetchU()
            if self.pop() == 0: self.cursor = t
        elif op == 57:
            t = (f2 << 16) | self.fetchU()
            if self.pop() != 0: self.cursor = t
        elif op == 58:
            self.stack[self.count + self.fetchS()] = 0
        elif op == 63:
            pass
        else:
            raise Exception(f'NULL op{op} executed at cursor {self.cursor-1}')
        self.steps += 1

if __name__ == '__main__':
    ram = open('D:/Documents/Default Project/work/psp_ram_jp.bin','rb').read()
    o = 0x08D2D000-0x08000000
    blk = ram[o:o+180224]  # TRUE units from block start (16B load hdr + 8B blk hdr, code at unit 12)
    units = list(struct.unpack('<%dH' % (len(blk)//2), blk))
    expect = [0,12,0,0,1,1,0,1,1,2,25047,4,0,1,1,43012,13,1,0,0,0,0,0,2,1,25174,18,1,2,0,2,28]
    import itertools
    for K in range(7, 13):
        for c18init in (1, 0):
            vm = VM(units)
            vm.stack = list(expect[:K]); vm.sp = K; vm.count = K
            vm.c18 = c18init
            try:
                while vm.steps < 300000:
                    if vm.cursor == 220:
                        got = [(v & 0xFFFFFFFF) for v in vm.stack[:32]]
                        exp = [(v & 0xFFFFFFFF) for v in expect]
                        mark = 'MATCH' if (got == exp and vm.sp == 32 and vm.count == 32) else 'diff'
                        print(f'K={K} c18={c18init}: {mark} steps={vm.steps} sp={vm.sp} count={vm.count}')
                        if mark == 'diff':
                            for i,(g,e) in enumerate(zip(got,exp)):
                                if g != e:
                                    print(f'   [{i}]: got {g} expect {e}')
                                    break
                        break
                    vm.step()
                else:
                    print(f'K={K} c18={c18init}: step limit')
            except Exception as e:
                print(f'K={K} c18={c18init}: STOP {e} steps={vm.steps} cursor={vm.cursor} sp={vm.sp} count={vm.count}')
