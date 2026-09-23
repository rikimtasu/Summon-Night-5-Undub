import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

path = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
d = open(path,'rb').read()
SEG_OFF = 0xC0
SEG_VADDR = 0x0
SEG_FILESZ = 0x242C94
code = d[SEG_OFF:SEG_OFF+SEG_FILESZ]

targets = {
    'comEvMsgEntVoiceBase': 2176453-SEG_OFF,
    'comEvMsgEntStrBase': 2176434-SEG_OFF,
    'voice_fmt': 2176478-SEG_OFF,  # '  voice %d' approx
}
print({k: hex(v) for k,v in targets.items()})

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
md.detail = True
# track last lui per reg
lui = {}
hits = {k: [] for k in targets}
addr2target = {v: k for k,v in targets.items()}
count = 0
for insn in md.disasm(code, SEG_VADDR):
    count += 1
    mn = insn.mnemonic
    ops = insn.op_str
    if mn == 'lui':
        # lui $r, imm
        try:
            parts = ops.split(',')
            reg = parts[0].strip()
            imm = int(parts[1].strip(), 0)
            lui[reg] = (insn.address, imm)
        except Exception:
            pass
    elif mn in ('addiu','addu','addi','daddiu'):
        try:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) == 3:
                dst, src, imm = parts
                immv = int(imm, 0)
                if immv & 0x8000: immv -= 0x10000
                if src in lui:
                    la, hiv = lui[src]
                    # only consider recent lui (within 20 insns?) - skip check for now
                    full = ((hiv << 16) + immv) & 0xFFFFFFFF
                    if full in addr2target:
                        hits[addr2target[full]].append((hex(insn.address), insn.mnemonic, ops, 'via %s lui@%s' % (src, hex(la))))
        except Exception:
            pass
print('disassembled', count)
for k, v in hits.items():
    print(k, len(v))
    for h in v[:10]:
        print('  ', h)
