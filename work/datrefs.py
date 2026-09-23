import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
path = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
d = open(path,'rb').read()
SEG_OFF=0xC0; SEG_FILESZ=0x242C94
code=d[SEG_OFF:SEG_OFF+SEG_FILESZ]
md=Cs(CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN)
md.detail=False
lui={}
refs={}
for insn in md.disasm(code, 0):
    if insn.mnemonic=='lui':
        try:
            r,i=insn.op_str.split(',')
            lui[r.strip()]=(insn.address,int(i.strip(),0))
        except: pass
    elif insn.mnemonic in ('addiu','addi'):
        try:
            p=[x.strip() for x in insn.op_str.split(',')]
            if len(p)==3:
                dst,src,im=p
                iv=int(im,0)
                if iv&0x8000: iv-=0x10000
                if src in lui:
                    la,hi=lui[src]
                    full=((hi<<16)+iv)&0xFFFFFFFF
                    # string region: file vaddr 0x210000-0x226000?
                    if 0x210000<=full<=0x226000:
                        fo=full+SEG_OFF
                        e=d.find(b'\x00',fo)
                        s=d[fo:e][:60]
                        if len(s)>=2 and all(32<=b<127 or b in (46,47,58,92) for b in s):
                            refs.setdefault(s.decode(),[]).append(hex(insn.address))
        except: pass
for k in sorted(refs):
    if '.DAT' in k or 'USRDIR' in k or 'disc0' in k:
        print(k, refs[k][:6])
