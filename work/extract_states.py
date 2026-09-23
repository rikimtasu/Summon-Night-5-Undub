import struct, sys
import zstandard
for name in ['NPJH50696_1.01_0.ppst','ULUS10656_1.01_0.ppst']:
    p = r'D:\Documents\Default Project\work\\' + name
    d = open(p,'rb').read()
    rev,comp,esize,usize = struct.unpack('<4I',d[:16])
    out = zstandard.ZstdDecompressor().decompress(d[176:176+esize], max_output_size=usize+16)
    assert len(out)==usize, (len(out),usize)
    # Memory section at 0x28, ver3: +20 pspmodel, +4 cookie, +4 memsize, RAM
    assert out[0x28:0x28+6]==b'Memory'
    p1 = 0x28+20
    memsize = struct.unpack('<I',out[p1+8:p1+12])[0]
    ram = out[p1+12:p1+12+memsize]
    assert len(ram)==memsize
    tag = 'jp' if name.startswith('NPJH') else 'usa'
    open(r'D:\Documents\Default Project\work\psp_ram_%s.bin'%tag,'wb').write(ram)
    print(tag,'memsize',hex(memsize),'ram ok')
