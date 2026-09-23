"""Two static probes for the script-block loader:

A) Search USA EBOOT for code materializing the block-header magic
   0x10000201 (lui 0x1000 + addiu 0x201) and 0x10000002, plus code
   touching header fields +0x08 (size) / +0x10 (c10).
B) Search 02.DAT and 10.DAT in both ISOs for a distinctive JP (UTF-8)
   prologue pool string and the USA string, in UTF-8/UTF-16/SJIS forms,
   to determine whether script text is stored plain or compressed.
"""
import struct, os, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

ROOT = r'D:\Documents\Default Project'
EBOOT = os.path.join(ROOT, 'EBOOT_USA_decrypted.bin')
SEG = 0xC0
CODE_LEN = 0x242C94

d = open(EBOOT, 'rb').read()
code = d[SEG:SEG + CODE_LEN]

print('=== A) EBOOT scans ===')
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = False
insns = list(md.disasm(code, 0))
lui = {}
magic_hits = []
for idx, ins in enumerate(insns):
    if ins.mnemonic == 'lui':
        r, v = ins.op_str.split(',')
        lui[r.strip()] = (idx, int(v.strip(), 0))
    elif ins.mnemonic in ('addiu', 'ori'):
        p = [x.strip() for x in ins.op_str.split(',')]
        if len(p) == 3 and p[1] in lui:
            li, hi = lui[p[1]]
            if idx - li <= 8:
                imm = int(p[2], 0)
                if imm & 0x8000:
                    imm -= 0x10000
                full = ((hi << 16) + imm) & 0xFFFFFFFF
                if full in (0x10000201, 0x10000002):
                    magic_hits.append((full, insns[li].address, ins.address))
print('magic 0x10000201/0x10000002 materializations:', len(magic_hits))
for f, a, b in magic_hits[:20]:
    print('   0x%08X lui@0x%X use@0x%X' % (f, a, b))

# stores to header fields: sw reg, 0x10(reg2) etc. followed by magic set
print()
print('context around each magic hit:')
for f, a, b in magic_hits[:4]:
    lo = max(0, b - 0x40)
    print('  --- use@0x%X ---' % b)
    for ins in md.disasm(code[lo:b + 0x40], lo):
        mark = '  <<<' if ins.address in (a, b) else ''
        print('    0x%X: %s %s%s' % (ins.address, ins.mnemonic, ins.op_str, mark))

print()
print('=== B) DAT text search ===')


def find_in_file(path, needle, lo, hi, chunk=8 << 20):
    hits = []
    L = len(needle)
    with open(path, 'rb') as f:
        f.seek(lo)
        base = lo
        tail = b''
        remaining = hi - lo
        while remaining > 0:
            buf = f.read(min(chunk, remaining))
            if not buf:
                break
            data = tail + buf
            start = base - len(tail)
            off = 0
            while True:
                i = data.find(needle, off)
                if i < 0:
                    break
                hits.append(start + i)
                off = i + 1
            tail = data[-(L - 1):]
            base += len(buf)
            remaining -= len(buf)
    return hits


# distinctive strings (from RAM pools)
jp_str = 'いらっしゃ～い'          # shop welcome (JP prologue pool)
usa_str = 'Welcome! How may I help you today?'
jp_str2 = 'むかし、むかし'          # second JP prologue string

CONT = {
    'USA': (os.path.join(ROOT, 'Summon Night 5 (USA).iso'),
            {'02.DAT': (328826880, 140421120), '10.DAT': (512131072, 2004992)}),
    'JP': (os.path.join(ROOT, 'Summon Night 5 (JP).iso'),
           {'02.DAT': (162758656, 139329536), '10.DAT': (115015680, 2015232)}),
}

for tag, (iso, dats) in CONT.items():
    strs = [jp_str, jp_str2, usa_str] if tag == 'JP' else [usa_str]
    for dat, (off, size) in dats.items():
        for s in strs:
            forms = {
                'utf8': s.encode('utf-8'),
                'utf16': s.encode('utf-16-le'),
                'sjis': s.encode('shift_jis', errors='replace'),
            }
            for fname, needle in forms.items():
                if len(needle) < 8:
                    continue
                hits = find_in_file(iso, needle, off, off + size)
                if hits:
                    print('%s %s %r [%s]: %d hits, first dat+%d'
                          % (tag, dat, s[:12], fname, len(hits), hits[0] - off))
        print('%s %s scanned' % (tag, dat), flush=True)
print('DONE', flush=True)
