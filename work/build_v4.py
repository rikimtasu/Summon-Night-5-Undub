"""Summon Night 5 (USA) undub v4 = v2 + split voice-hook.

v3 died: its single cave+table sat in image ranges that never reach RAM
(game work buffer + loader-dead zone, mapped via canary/probe builds).
v4 splits the payload across 14 probe-PROVEN gaps (pattern-fill survived
boot->title 100% intact):
 - code + chunk descriptors in gap 0x224868 (runtime 0x08A28868)
 - 339-entry table (c10, offset, vid) chunked across the other 13 gaps
Hook: same site as v3r2 (0x17848 j + 0x1784C sw-delay; loader-clean).
Built fresh from decrypted EBOOT (no canary/probe leftovers).
"""
import struct
import pickle
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_undub_v2 as v2

SRC_EBOOT = v2.SRC_EBOOT
PATCHED_EBOOT = v2.PATCHED_EBOOT
SEG = 0xC0
RT = 0x08804000

CODE_FVA = 0x224868
CODE_RT = CODE_FVA + RT
HOOK_FVA = 0x17848
RET_FVA = 0x17858
QUEUE_FN_RT = 0x820C + RT

V2_NOPS = {0x17904: 0x0205282B, 0x17908: 0x54A00001, 0x1790C: 0x2410FFFF}
HOOK_EXPECT = {0x17848: 0xAFA20008, 0x1784C: 0x02402025}

# proven chunk homes (fva, len) -- probe-2 FULL-intact gaps
CHUNK_HOMES = [
    (0x2334F4, 648), (0x22E33C, 496), (0x2242B8, 396), (0x22FEC0, 380),
    (0x2240E4, 380), (0x223C40, 332), (0x22B760, 332), (0x22D164, 332),
    (0x223E30, 304), (0x224F20, 288), (0x22F2F0, 280), (0x224B28, 280),
    (0x22FAFE, 256),
]
CODE_GAP_LEN = 664


def J(t):
    return 0x08000000 | ((t >> 2) & 0x03FFFFFF)


def BNE(rs, rt, imm):
    return (0x05 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def load_entries():
    out = []
    with open(r'D:\Documents\Default Project\work\v3_entries.txt') as f:
        for line in f:
            key, vid, _ju, _uu = line.split()
            out.append((38381, int(key), int(vid)))
    out.sort()
    return out


def partition(entries):
    """Greedily fill chunk homes in order. Returns [(fva, [entries])]."""
    chunks = []
    idx = 0
    for (fva, ln) in CHUNK_HOMES:
        cap = ln // 12
        take = entries[idx:idx + cap]
        if not take:
            break
        chunks.append((fva, take))
        idx += len(take)
    assert idx == len(entries), f'{len(entries) - idx} entries homeless!'
    return chunks


def assemble(chunks):
    """Returns (code_words, descr_words, chunk_blobs)."""
    K = len(chunks)
    # word indices
    I_SCAN, I_ADV, I_CHUNK, I_DOCALL = 11, 22, 9, 26
    code = [
        0xAFA20008,  # 0 sw v0,8(sp)
        0x02402025,  # 1 or a0,s2,zero
        0x8E08001C,  # 2 lw t0,0x1C(s0)  stream
        0x8E090010,  # 3 lw t1,0x10(s0)  c10
        0x8FAA0000,  # 4 lw t2,0(sp)     p0
        0x01485023,  # 5 subu t2,t2,t0   key
        0,  # 6 lui t3,HI(descr)
        0,  # 7 ori t3,LO(descr)
        0x340C0000 | K,  # 8 ori t4,zero,K
        0x8D6D0000,  # 9 chunk: lw t5,0(t3)
        0x8D6E0004,  # 10 lw t6,4(t3)
        0x8DA20000,  # 11 scan: lw v0,0(t5)
        0,  # 12 bne v0,t1,adv
        0x00000000,  # 13 nop
        0x8DA20004,  # 14 lw v0,4(t5)
        0,  # 15 bne v0,t2,adv
        0x00000000,  # 16 nop
        0x8DA20008,  # 17 lw v0,8(t5)
        0x8E4D0030,  # 18 lw t5,0x30(s2)
        0xADA2001C,  # 19 sw v0,0x1C(t5)
        0,  # 20 j docall
        0x00000000,  # 21 nop
        0x25AD000C,  # 22 adv: addiu t5,t5,12
        0x25CEFFFF,  # 23 addiu t6,t6,-1
        0,  # 24 bne t6,zero,scan
        0x00000000,  # 25 nop
        0x256B0008,  # 26 cnext: addiu t3,t3,8
        0x258CFFFF,  # 27 addiu t4,t4,-1
        0,  # 28 bne t4,zero,chunk
        0x00000000,  # 29 nop
        0x02402021,  # 30 docall: move a0,s2
        0x0C000000 | ((QUEUE_FN_RT >> 2) & 0x03FFFFFF),  # 31 jal queue
        0x001D2821,  # 32 move a1,sp (delay)
        0,  # 33 j RET
        0x00000000,  # 34 nop
    ]
    assert len(code) == 35
    descr_rt = CODE_RT + 35 * 4
    code[6] = 0x3C0B0000 | ((descr_rt >> 16) & 0xFFFF)
    code[7] = 0x356B0000 | (descr_rt & 0xFFFF)
    A = lambda i: CODE_RT + i * 4
    # MIPS branch: target = branch + 4 + imm*4  =>  imm = (target-branch-4)/4
    code[12] = BNE(2, 9, (A(I_ADV) - A(12) - 4) // 4)
    code[15] = BNE(2, 10, (A(I_ADV) - A(15) - 4) // 4)
    code[20] = J(A(I_DOCALL))
    code[24] = BNE(14, 0, (A(I_SCAN) - A(24) - 4) // 4)
    code[28] = BNE(12, 0, (A(I_CHUNK) - A(28) - 4) // 4)
    code[33] = J(RET_FVA + RT)
    descr = []
    for (fva, _) in chunks:
        descr += [(fva + RT) & 0xFFFFFFFF, 0]  # count patched below
    blobs = []
    for ((fva, ents), i) in zip(chunks, range(len(chunks))):
        descr[2 * i + 1] = len(ents)
        w = []
        for (c10, off, vid) in ents:
            w += [c10, off, vid]
        assert len(w) * 4 <= [l for (a, l) in CHUNK_HOMES if a == fva][0]
        blobs.append((fva, w))
    return code, descr, blobs


def make_eboot():
    """Patch a fresh EBOOT (v2 NOPs + hook + split table). Returns nothing;
    writes PATCHED_EBOOT. Safe to call without rebuilding the ISO."""
    diff = pickle.loads(open(r'D:\Documents\Default Project\work\usa_loader_diff.pkl', 'rb').read())
    d = bytearray(open(SRC_EBOOT, 'rb').read())
    for fva, exp in V2_NOPS.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'v2 word at {fva:#x} = {cur:#x}'
        d[off:off + 4] = b'\x00\x00\x00\x00'
    print('v2 clamp NOPed')
    for fva, exp in HOOK_EXPECT.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'hook word at {fva:#x} = {cur:#x}'
    d[SEG + HOOK_FVA:SEG + HOOK_FVA + 4] = struct.pack('<I', J(CODE_RT))
    d[SEG + HOOK_FVA + 4:SEG + HOOK_FVA + 8] = struct.pack('<I', 0xAFA20008)
    print(f'hook installed: j {CODE_RT:#x} at fva {HOOK_FVA:#x}')

    entries = load_entries()
    chunks = partition(entries)
    print(f'{len(entries)} entries in {len(chunks)} chunks')
    code, descr, blobs = assemble(chunks)

    # safety: every written word must be loader-clean file-zero
    blob = struct.pack('<%dI' % len(code), *code) + struct.pack('<%dI' % len(descr), *descr)
    assert len(blob) <= CODE_GAP_LEN, len(blob)
    here = list(range(CODE_FVA, CODE_FVA + len(blob), 4))
    assert not any(h in diff for h in here), 'code hits loader fixups!'
    cur = d[SEG + CODE_FVA:SEG + CODE_FVA + len(blob)]
    assert all(b == 0 for b in cur), 'code home not zero!'
    d[SEG + CODE_FVA:SEG + CODE_FVA + len(blob)] = blob
    for (fva, w) in blobs:
        assert not any(x in diff for x in range(fva, fva + len(w) * 4, 4)), f'chunk {fva:#x} hits fixups!'
        off = SEG + fva
        cur = d[off:off + len(w) * 4]
        assert all(b == 0 for b in cur), f'chunk {fva:#x} not zero!'
        d[off:off + len(w) * 4] = struct.pack('<%dI' % len(w), *w)
    print(f'code+descr ({len(blob)}B) at fva {CODE_FVA:#x}; {len(blobs)} table chunks placed')

    with open(PATCHED_EBOOT, 'wb') as f:
        f.write(d)
    print(f'patched EBOOT: {PATCHED_EBOOT} ({len(d)} bytes)')


def main():
    make_eboot()
    v2.swap_voice_archives()
    v2.patch_eboot_extent()
    print('done:', v2.OUT_ISO)


if __name__ == '__main__':
    main()
