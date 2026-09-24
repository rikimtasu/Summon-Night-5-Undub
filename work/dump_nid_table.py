# -*- coding: utf-8 -*-
"""Resolve the import NID table to stub addresses, then find the I/O callers.

A packed NID table sits at ~0x211DC4. Identifying NIDs by name worked for 14
of them; the ones that matter (sceIoRead, the sceUtilitySavedata family) are
either absent or carry values I had wrong. Two things to establish:

  1. What is the table's structure? Dump it as u32 and flag entries that look
     like code pointers (0x08804000..0x08A50000) versus NID words. If stub
     addresses are interleaved, NID -> stub falls out immediately.

  2. Find the PSP library descriptor that points at this table. A module's
     lib entry holds {nids*, entries*}; locating a pointer to 0x08A15DC4
     (runtime form of fva 0x211DC4) yields the parallel stub array.

Once we have stub addresses we can enumerate CALLERS by byte-searching the
code for jal encodings - real call edges, with no string-addressing assumptions
left to get wrong. The read path's callers are where the transform lives.
"""
import struct

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
RT = 0x08804000
d = open(P, 'rb').read()

KNOWN = {
    0x1F803938: 'sceCtrlReadBufferPositive',
    0xAB49E76A: 'sceGeListEnQueue',
    0x289D82FE: 'sceDisplaySetFrameBuf',
    0x27CC57F0: 'sceKernelLibcTime',
    0x369ED59D: 'sceKernelGetSystemTimeLow',
    0xF475845D: 'sceKernelStartThread',
    0x446D8DE6: 'sceKernelCreateThread',
    0x9ACE131E: 'sceKernelSleepThread',
    0x1839852A: 'sceKernelLibcClock',
    0x42EC03AC: 'sceIoWrite',
    0xB29DDF9C: 'sceIoChstat',
    0x109F50BC: 'sceIoOpen',
    0x27EB27B8: 'sceIoLseek',
    0x9A1C91D7: 'sceUtilityMsgDialogGetStatus',
    # candidates whose presence we are testing
    0x6A638FD8: '?sceIoRead',
    0x810C4BCB: '?sceIoClose',
    0x50F4AC0A: '?sceUtilitySavedataInitStart',
    0xD4B95AB8: '?sceUtilitySavedataUpdate',
    0x6332AA39: '?sceUtilitySavedataGetStatus',
    0x97B79670: '?sceUtilitySavedataShutdownStart',
    0x7DF5B489: '?sceUtilitySavedataShutdownStart(alt)',
    0xB6D703F6: '?sceUtilityShutdownStart',
    0x2A2B3DE0: '?sceUtilityLoadAvMenu',
    0xC98DE6B7: '?sceKernelFreePartitionMemory',
    0x1B42A3B7: '?sceKernelPartitionMaxFreeMemSize',
    0x5265B2E1: '?sceKernelPartitionTotalFreeMemSize',
    0x927A2794: '?sceKernelPartitionAllocMemory',
    0xB3055D7F: '?sceKernelQueryMemoryInfo',
    0x9D9A5BA1: '?sceKernelGzipDecompress',
    0x78E5B0F1: '?sceKernelGzipIsValid',
    0x4E709F1E: '?sceKernelDecompress... ',
}

print('=== NID table dump 0x211D80..0x2120C0 ===')
base = 0x211D80
end = 0x2120C0
prev_known = False
for off in range(base, end, 4):
    w = struct.unpack_from('<I', d, off)[0]
    is_rt = 0x08804000 <= w < 0x08B00000
    name = KNOWN.get(w)
    if name:
        print('  0x%06X: %08X   <== %s' % (off, w, name))
        prev_known = True
    elif is_rt:
        print('  0x%06X: %08X   [code/data ptr -> fva 0x%X]'
              % (off, w, w - RT))
        prev_known = True
    else:
        # only print unknowns that sit between known hits, to keep it readable
        if prev_known:
            print('  0x%06X: %08X' % (off, w))

print('\n=== pointers TO the NID table (runtime and fva forms) ===')
for label, needle in (('runtime 0x%08X' % (RT + 0x211DC4),
                       struct.pack('<I', RT + 0x211DC4)),
                      ('fva 0x00211DC4', struct.pack('<I', 0x211DC4)),
                      ('runtime of 0x211D00 %08X' % (RT + 0x211D00),
                       struct.pack('<I', RT + 0x211D00)),
                      ('fva 0x00211D00', struct.pack('<I', 0x211D00))):
    s, locs = 0, []
    while True:
        i = d.find(needle, s)
        if i < 0:
            break
        locs.append(i)
        s = i + 1
    print('  %-28s -> %s' % (label, ', '.join('0x%X' % l for l in locs[:8])
                             or 'none'))

print('\n=== every distinct u32 NID-looking word in 0x211D80..0x2120C0 ===')
vals = [struct.unpack_from('<I', d, o)[0] for o in range(0x211D80, 0x2120C0, 4)]
nids = [v for v in vals if not (0x08804000 <= v < 0x08B00000) and v > 0x1000]
print('  %d NID-like words out of %d total' % (len(nids), len(vals)))
print('  (names known for: %s)' % ', '.join(
    KNOWN[v] for v in nids if v in KNOWN and not KNOWN[v].startswith('?')))
print('DONE')
