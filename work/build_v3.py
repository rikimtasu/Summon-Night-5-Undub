"""Summon Night 5 (USA) undub v3 = v2 + voice-hook.

v2: JP SV00-17 swap + NOP'd story-voice clamp in USA EBOOT slot-65 handler.
v3 adds: hook in USA slot-64 (text-display) handler tail that fires the 339
script-deleted story voices via a baked (c10, text-offset -> voice-id) table.

Hook site (USA EBOOT fva; both words loader-fixup-free, verified vs RAM diff):
    0x17848  sw v0, 8(sp)       ->  j CAVE
    0x1784C  or a0, s2, zero    ->  sw v0, 8(sp)   (delay slot, displaced)
    0x17850  jal (loader-patched at boot; dead, never executed)
Cave at fva 0x236378 (runtime 0x08A3A374, loader-untouched zero gap in RWX
seg0) + 339-entry table (c10=u32, text-offset=u32, voice-id=u32;
key = strptr - stream, c10 = ctx+0x10). On hit: voice store replica
(lw t3,0x30(s2) / sw vid,0x1C(t3)); then displaced or a0,s2 + jal voice-queue
fn (runtime 0x0880C20C) + j 0x0881B858.
"""
import os
import struct
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_undub_v2 as v2

SRC_EBOOT = v2.SRC_EBOOT
PATCHED_EBOOT = v2.PATCHED_EBOOT
SEG = 0xC0

CAVE_FVA = 0x236378  # loader-untouched zero gap (verified vs RAM diff)
CAVE_RT = CAVE_FVA + 0x08804000
HOOK_FVA = 0x17848  # j CAVE ; delay = displaced sw v0,8(sp)
RET_FVA = 0x17858
QUEUE_FN_RT = 0x820C + 0x08804000  # USA queue wrapper runtime (file fva 0x820c)

# v2 clamp NOPs
V2_NOPS = {0x17904: 0x0205282B, 0x17908: 0x54A00001, 0x1790C: 0x2410FFFF}
# hook-site expected file words (0x17850 left alone: loader-patched jal, dead)
HOOK_EXPECT = {0x17848: 0xAFA20008, 0x1784C: 0x02402025}


def J(target_rt):
    return 0x08000000 | ((target_rt >> 2) & 0x03FFFFFF)


def BNE(rs, rt, imm):
    return (0x05 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def assemble(entries):
    """entries: [(c10, offset, vid)]. Returns (code_words, table_words).

    Layout (word idx):
      0  sw v0,8(sp)      (displaced, runs in hook-j delay slot position... actually
                           cave prologue: v0 saved before use as scratch)
      1  or a0,s2,zero    (displaced move)
      2  lw t0,0x1C(s0)   stream
      3  lw t1,0x10(s0)   c10
      4  lw t2,0(sp)      p0
      5  subu t2,t2,t0    key = offset
      6  lui t3,HI(table)
      7  ori t3,t3,LO(table)
      8  ori t0,zero,n    counter
      9  scan: lw v0,0(t3)
      10 bne v0,t1,adv
      11 nop
      12 lw v0,4(t3)
      13 bne v0,t2,adv
      14 nop
      15 lw v0,8(t3)
      16 lw t3,0x30(s2)
      17 sw v0,0x1C(t3)
      18 j docall
      19 nop
      20 adv: addiu t3,t3,12
      21 addiu t0,t0,-1
      22 bne t0,zero,scan
      23 nop
      24 docall: move a0,s2
      25 jal QUEUE_FN_RT
      26 move a1,sp       (delay)
      27 j RET_RT
      28 nop
    """
    n = len(entries)
    assert n < 65536
    code_len = 29
    table_rt = CAVE_RT + code_len * 4
    HI = (table_rt >> 16) & 0xFFFF
    LO = table_rt & 0xFFFF
    RET_RT = RET_FVA + 0x08804000
    DOCALL_RT = CAVE_RT + 24 * 4
    SCAN_RT = CAVE_RT + 9 * 4
    ADV_RT = CAVE_RT + 20 * 4
    code = [
        0xAFA20008,  # sw v0,8(sp)
        0x02402025,  # or a0,s2,zero
        0x8E08001C,  # lw t0,0x1C(s0)
        0x8E090010,  # lw t1,0x10(s0)
        0x8FAA0000,  # lw t2,0(sp)
        0x01485023,  # subu t2,t2,t0
        0x3C0B0000 | HI,  # lui t3,HI
        0x356B0000 | LO,  # ori t3,t3,LO
        0x34080000 | n,  # ori t0,zero,n
        0x8D620000,  # scan: lw v0,0(t3)
        0,  # bne v0,t1,adv (patched below)
        0x00000000,
        0x8D620004,
        0,  # bne v0,t2,adv (patched below)
        0x00000000,
        0x8D620008,
        0x8E4B0030,
        0xAD62001C,
        J(DOCALL_RT),
        0x00000000,
        0x256B000C,
        0x2508FFFF,
        0,  # bne t0,zero,scan (patched below)
        0x00000000,
        0x02402021,  # docall: move a0,s2
        0x0C000000 | ((QUEUE_FN_RT >> 2) & 0x03FFFFFF),
        0x001D2821,  # move a1,sp (delay)
        J(RET_RT),
        0x00000000,
    ]
    # fix branch offsets explicitly (imm = (target - (branch+8)) / 4)
    code[10] = BNE(2, 9, (ADV_RT - (CAVE_RT + 10 * 4 + 8)) // 4)
    code[13] = BNE(2, 10, (ADV_RT - (CAVE_RT + 13 * 4 + 8)) // 4)
    code[22] = BNE(8, 0, (SCAN_RT - (CAVE_RT + 22 * 4 + 8)) // 4)
    assert len(code) == code_len
    table = []
    for (c10, off, vid) in entries:
        table += [c10 & 0xFFFFFFFF, off & 0xFFFFFFFF, vid & 0xFFFFFFFF]
    return code, table


def load_entries():
    entries = []
    with open(r'D:\Documents\Default Project\work\v3_entries.txt') as f:
        for line in f:
            key, vid, _ju, _uu = line.split()
            entries.append((38381, int(key), int(vid)))
    return entries


def make_patched_eboot():
    import pickle
    loader_diff = pickle.loads(
        open(r'D:\Documents\Default Project\work\usa_loader_diff.pkl', 'rb').read())
    # safety: loader must not touch our hook words or cave range
    hot = [HOOK_FVA, HOOK_FVA + 4]
    assert not any(h in loader_diff for h in hot), 'hook site has loader fixups!'
    d = bytearray(open(SRC_EBOOT, 'rb').read())
    for fva, exp in V2_NOPS.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'v2 word at {fva:#x} = {cur:#x}, expected {exp:#x}'
        d[off:off + 4] = b'\x00\x00\x00\x00'
    print('v2 clamp NOPed')
    for fva, exp in HOOK_EXPECT.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'hook word at {fva:#x} = {cur:#x}, expected {exp:#x}'
    d[SEG + HOOK_FVA:SEG + HOOK_FVA + 4] = struct.pack('<I', J(CAVE_RT))
    d[SEG + HOOK_FVA + 4:SEG + HOOK_FVA + 8] = struct.pack('<I', 0xAFA20008)
    print(f'hook installed: j {CAVE_RT:#x} at fva {HOOK_FVA:#x} '
          f'(0x17850 left for loader fixup, dead)')

    entries = load_entries()
    print(f'table entries: {len(entries)}')
    code, table = assemble(entries)

    # cave must be zeros AND loader-untouched
    cave_off = SEG + CAVE_FVA
    blob = struct.pack('<%dI' % len(code), *code) + struct.pack('<%dI' % len(table), *table)
    cur = d[cave_off:cave_off + len(blob)]
    assert all(b == 0 for b in cur), 'cave not zeroed!'
    touched = [a for a in loader_diff if CAVE_FVA <= a < CAVE_FVA + len(blob)]
    assert not touched, f'loader touches cave: {[hex(a) for a in touched]}'
    d[cave_off:cave_off + len(blob)] = blob
    print(f'cave written at fva {CAVE_FVA:#x} ({len(blob)} bytes: '
          f'{len(code) * 4} code + {len(table) * 4} table)')

    with open(PATCHED_EBOOT, 'wb') as f:
        f.write(d)
    print(f'patched EBOOT: {PATCHED_EBOOT} ({len(d)} bytes)')


if __name__ == '__main__':
    make_patched_eboot()
    v2.swap_voice_archives()
    v2.patch_eboot_extent()
    print('done:', v2.OUT_ISO)
