import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
path = r'D:\Documents\Default Project\EBOOT_JP_decrypted.bin'
d = open(path,'rb').read()
SEG_OFF=0xC0; SEG_FILESZ=0x21AE00
code=d[SEG_OFF:SEG_OFF+SEG_FILESZ]
md=Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN)
targets = {'svfmt1':0x1f38a0,'svfmt2':0x1f38f8,'sv00':0x1f3774}
lui={}; hits={k:[] for k in targets}
addr2t={v:k for k,v in targets.items()}
for insn in md.disasm(code,0):
    if insn.mnemonic=='lui':
        try:
            r,i=insn.op_str.split(','); lui[r.strip()]=(insn.address,int(i.strip(),0))
        except: pass
    elif insn.mnemonic in ('addiu','addi'):
        try:
            p=[x.strip() for x in insn.op_str.split(',')]
            if len(p)==3:
                dst,src,im=p
                iv=int(im,0)
                if iv&0x8000: iv-=0x10000
                if src in lui:
                    la,hi=lui[src]; full=((hi<<16)+iv)&0xFFFFFFFF
                    if full in addr2t:
                        hits[addr2t[full]].append(hex(insn.address))
        except: pass
for k,v in hits.items():
    print(k,v[:10])
