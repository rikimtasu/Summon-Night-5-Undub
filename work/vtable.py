import struct
path = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
d = open(path,'rb').read()
SEG_OFF=0xC0; SEG_FILESZ=0x242C94
seg=d[SEG_OFF:SEG_OFF+SEG_FILESZ]
n=len(seg)//4
words=struct.unpack('<%dI'%n, seg[:n*4])
# candidate handler range: 0x17000-0x1B000 (event handlers seen at 0x17760,0x1787C)
lo,hi=0x17000,0x1D000
idx=[i for i,w in enumerate(words) if lo<=w<hi]
print('words in handler range:',len(idx))
# find runs of >=8 consecutive words all in range (dispatch tables)
runs=[];cur=[]
for i in idx:
    if cur and i-cur[-1]<=2:
        cur.append(i)
    else:
        if cur: runs.append(cur)
        cur=[i]
if cur: runs.append(cur)
runs.sort(key=len,reverse=True)
for r in runs[:10]:
    print('run len',len(r),'at file vaddr',hex(r[0]*4),'words:',[hex(words[i]) for i in r[:16]])
