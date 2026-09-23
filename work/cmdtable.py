import struct, re
path = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
d = open(path,'rb').read()
SEG_OFF = 0xC0
# collect comEv names file offsets -> vaddr
names = sorted(set(m.group(0) for m in re.finditer(rb'comEv[A-Za-z]+', d)))
name_vaddrs = {}
for n in names:
    fo = d.find(n)
    name_vaddrs[n.decode()] = fo - SEG_OFF
print('names:', len(name_vaddrs))
# build set of vaddr values
vset = set(name_vaddrs.values())
# scan 4-byte LE words in segment0 for these values
SEG_FILESZ = 0x242C94
seg = d[SEG_OFF:SEG_OFF+SEG_FILESZ]
hits = []  # (word_offset_vaddr, value)
import array
n = len(seg)//4
words = struct.unpack('<%dI' % n, seg[:n*4])
for i,w in enumerate(words):
    if w in vset:
        hits.append((i*4, w))
print('pointer hits:', len(hits))
# cluster: sort by offset, find runs within 64 bytes
hits.sort()
runs = []
cur = [hits[0]]
for h in hits[1:]:
    if h[0]-cur[-1][0] <= 64:
        cur.append(h)
    else:
        runs.append(cur); cur=[h]
runs.append(cur)
runs.sort(key=len, reverse=True)
v2n = {v:k for k,v in name_vaddrs.items()}
for r in runs[:8]:
    print('run len', len(r), 'from', hex(r[0][0]), 'to', hex(r[-1][0]))
    for off,v in r[:24]:
        print('  ', hex(off), v2n[v])
    print()
