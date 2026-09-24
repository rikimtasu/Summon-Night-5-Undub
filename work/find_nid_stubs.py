# -*- coding: utf-8 -*-
"""Locate the PSP kernel import stubs, then the save I/O callers.

Why this is the right next probe. Everything so far was string xref, and it
has hit a structural wall:

  * the anchors 'DATA.BIN', 'ms0:/PSP/SAVEDATA/%s%s/%s', 'SAVELOAD_PAC is not
    read!' have NO lui/addiu consumer (full 32-bit materialisation)
  * and NO raw u32 pointer entry anywhere in the file (so not a pointer table)
  * and $gp is not set in the first 0x800, so not gp-relative either

The remaining possibility is register-derived addresses
(addiu $r,$r,off from a base already holding a nearby string), which a
materialisation scan cannot see at all. Rather than build a dataflow engine,
anchor on something unambiguous instead: the NIDs.

A retail PSP EBOOT keeps its import table as NID words. The well-known ones
give us the stubs directly, and from a stub we can enumerate CALLERS - real
code, no string addressing assumptions. Then:

    caller of sceIoRead  ->  the buffer
    caller of sceIoWrite ->  the buffer
    and the code between read and use IS the transform.

Test a list of known NIDs; print which are present and where.
"""
import struct

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
SEG = 0xC0
d = open(P, 'rb').read()

# name -> NID (well-known PSP libc / KernelLib / sceUtility exports)
NIDS = [
    ('sceIoOpen',            0x109F50BC),
    ('sceIoOpenAsync',       0x810C4BCB and 0xC52DE26B),
    ('sceIoClose',           0x810C4BCB),
    ('sceIoRead',            0x6A638FD8),
    ('sceIoReadAsync',       0xA0B2A675),
    ('sceIoWrite',           0x42EC03AC),
    ('sceIoWriteAsync',      0x0FACABEB),
    ('sceIoLseek',           0x27EB27B8),
    ('sceIoLseek32',         0x683ED7BC),
    ('sceIoDevctl',          0x71F11DAD),
    ('sceIoGetstat',         0x54F5FB80),
    ('sceIoChstat',          0xB29DDF9C),
    ('sceIoDopen',           0xB29DDF9C and 0x1B8DC5A6),
    ('sceIoDread',           0xE3EB0097),
    ('sceIoDclose',          0xEB14769F),
    ('sceIoRemove',          0x0C72D612),
    ('sceIoRename',          0x77BA29DF),
    ('sceIoMkdir',           0xE95AEB73),
    ('sceKernelCreateSema',  0xE1618451),
    ('sceKernelSignalSema',  0x3F53E640),
    ('sceKernelWaitSema',    0x36918DBE),
    ('sceKernelCreateThread',0x446D8DE6),
    ('sceKernelStartThread', 0xF475845D),
    ('sceKernelMemcpy',      0x93533275 and 0x129B82D7),
    ('sceKernelMemset',      0x9A7D3A22 and 0xA74B8C1D),
    ('sceKernelLibcClock',   0x1839852A),
    ('sceRtcGetCurrentClock',0xC41C2559),
    ('sceDisplaySetFrameBuf',0x289D82FE),
    ('scePowerSetClockFrequency', 0x737486F2),
    ('sceGeListEnQueue',     0xAB49E76A),
    ('sceGuStart',           0xE0092D4C and 0x0534C50A),
    ('sceUtilityGetSystemParamInt', 0xA5DA2406),
    ('sceUtilitySavedataInitStart', 0x50F4AC0A),
    ('sceUtilitySavedataShutdownStart', 0x97B79670),
    ('sceUtilitySavedataGetStatus', 0x6332AA39),
    ('sceUtilitySavedataUpdate', 0xD4B95AB8),
    ('sceUtilityMsgDialogGetStatus', 0x9A1C91D7),
    ('sceKernelUtilsMt19937UInt', 0xE7E654B8),
    ('sceKernelGetLowestThreadPriority', 0xD8199AC4),
    ('sceKernelCpuSuspendIntr', 0x092D3C4F),
    ('sceKernelCpuResumeIntr', 0x7591C7DB),
    ('sceKernelCreateCallback', 0xC11BA0C4),
    ('sceKernelPollCallback', 0x27E2B65B),
    ('sceKernelCheckCallback', 0x7331C027),
    ('sceKernelSleepThread', 0x9ACE131E),
    ('sceKernelDelayThread', 0xDBCE331D),
    ('sceKernelGetSystemTimeLow', 0x369ED59D),
    ('sceKernelLibcTime',    0x27CC57F0),
    ('sceKernelGetModuleList', 0x9CD57137),
    ('sceKernelLoadModule',  0x97CE8E92),
    ('sceKernelStartModule', 0x70582246),
    ('sceAtrac3plus',        0xD5C28CC0),
    ('sceMpegInit',          0xE404244D),
    ('sceWlanGetSwitchState', 0xD10F91D2),
    ('sceCtrlSetSamplingCycle', 0x6A2774F3),
    ('sceCtrlReadBufferPositive', 0x1F803938),
    ('sceCtrlPeekBufferPositive', 0x3A622550),
    ('sceIoChdir',           0x55F4717D),
    ('sceIoSync',            0x9E9F8D0D),
    ('sceIoCloseAll',        0x66B72822),
]

print('=== NID presence scan ===')
hits = {}
for name, nid in NIDS:
    enc = struct.pack('<I', nid)
    locs, s = [], 0
    while True:
        i = d.find(enc, s)
        if i < 0:
            break
        locs.append(i)
        s = i + 1
    if locs:
        hits[name] = locs
        print('  HIT  %-32s 0x%08X  x%d at %s'
              % (name, nid, len(locs),
                 ', '.join('0x%X' % l for l in locs[:5])))
    else:
        print('  ---  %-32s 0x%08X' % (name, nid))

print('\n=== summary: %d/%d NIDs present ===' % (len(hits), len(NIDS)))
for k in hits:
    print('   %s' % k)
print('DONE')
