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
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


# backlog-replay voice hook: replay fn 0xDE3E8 reads backlog entry (s2)
# but never plays its voice (+0x04). Hook at 0xDE430 (loader-clean, no
# branches in) to store entry voice id to voiceobj+0x1C when != -1.
# s2=entry live; t0/t1 proven free in region; s0 set by displaced move.
REPLAY_HOOK_FVA = 0xDE430
REPLAY_RET_FVA = 0xDE438
REPLAY_HOOK_EXPECT = {0xDE430: 0x00808025, 0xDE434: 0x8E050010}
# gap repack (gap = 664B, walker+descr = 228B -> 436B of slack):
#   228..360 replay cave (33w) | 360..468 log cave (27w)
#   468..568 gate cave (25w)   | 568..636 replay recorder (68B)
#   636..648 log recorder (12B)| 648..660 gate recorder (12B)
REPLAY_CAVE_FVA = CODE_FVA + 228  # 33 words -> ends +360
REPLAY_RC_FVA = CODE_FVA + 568  # flight recorder: count + 8x(entry,vid)
GLOBAL_VAR_RT = 0x08A27508  # engine-obj-ptr variable; file off 0x223508 IS a
# loader fixup (word is 0 on disc, loader fills it) - the cave only READS it
# at runtime, i.e. after the loader applied it, so this is fine
# logger copy hook: backlog logger 0xDDD20 snapshots entries (voice at +0x04)
# but replay reads +0x08 (0/-1 in USA, vid in JP). Copy pair-range +0x04
# into +0x08 so replay voices pair lines. s1=entry live; a0/a1/t0 dead
# (clobbered by the jals at 0xddf5c/0xddf70). Recorder: count +
# last (entry, vid-at-fire) to prove the hook fires and what +0x04 held.
#
# ROUND-5 crash fix -- hook was at 0xDDF7C (j) with 0xDDF80 = nop delay:
# full-text branch audit shows 0xddf4c beqz -> 0xddf80 lands ON that delay
# slot (first render: 0x14(s1)==0), skipping the cave -> displaced
# `ori s4,zero,0` never ran -> a0 = stale s4 + s1 overflowed RAM ->
# `sb s3,0x25(a0)` faulted at 0x11bd63c5 (0x11bd63a0+0x25), PC reported
# at the branch-target block 0x088e1f80. All recorders read 0 because the
# cave never executed once.
# New layout: j at 0xDDF80 (replaces ori), delay slot 0xDDF84 stays NATIVE
# stock (`move s5,s1` -- never zeroed; no branch lands on it), displaced =
# ori only, ret = 0xDDF88 (`addu a0,s4,s1`; the 0xddfd8 bnez loop
# back-edge lands here and must skip the cave so the char counter survives).
# Every logger path now funnels through the cave.
LOG_HOOK_FVA = 0xDDF80
LOG_RET_FVA = 0xDDF88
LOG_HOOK_EXPECT = {0xDDF80: 0x34140000}  # ori s4, zero, 0 (replaced by j)
# stock words that must remain byte-identical after the patch:
LOG_NATIVE = {0xDDF7C: 0xAE340014,  # sw s4, 0x14(s1)
              0xDDF84: 0x0220A825,  # move s5, s1  (delay slot: NATIVE)
              0xDDF88: 0x02912021}  # addu a0, s4, s1 (ret)
LOG_CAVE_FVA = CODE_FVA + 360  # 25 words -> ends +460 (slot 108B)
LOG_RC_FVA = CODE_FVA + 636  # count + entry + vid (12B)


def log_cave():
    rt = LOG_CAVE_FVA + RT
    lrc = LOG_RC_FVA + RT
    ret = LOG_RET_FVA + RT
    code = [
        ORI(0, 20, 0),  # 0 ori s4, zero, 0 (displaced; 0xddf84 delay native)
        LUI(8, (lrc >> 16) & 0xFFFF),  # 1 lui t0, HI(LRC)
        ORI(8, 8, lrc & 0xFFFF),  # 2 ori t0, LO(LRC)
        SW(8, 17, 4),  # 3 sw s1, 4(t0) (rec entry)
        LW(17, 4, 4),  # 4 lw a0, 4(s1) (vid at fire, a0 dead)
        SW(8, 4, 8),  # 5 sw a0, 8(t0) (rec vid)
        LW(8, 5, 0),  # 6 lw a1, 0(t0) (count)
        ADDIU(5, 5, 1),  # 7 addiu a1, 1
        SW(8, 5, 0),  # 8 sw a1, 0(t0)
        LW(17, 5, 8),  # 9 lw a1, 8(s1) (cur +0x08)
        ADDIU(5, 5, 1),  # 10 addiu a1, 1 (0->1, -1->0)
        SLTIU(5, 5, 2),  # 11 sltiu a1, a1, 2 -> 1 iff cur in {0, -1}
        0,  # 12 beqz a1, SKIP (not empty; patched below)
        0x00000000,  # 13 nop
        ORI(0, 5, 0x8C00),  # 14 ori a1, zero, 0x8C00 (pair lo)
        SLTU(4, 5, 5),  # 15 sltu a1, a0, a1 (vid < lo)
        0,  # 16 bnez a1, SKIP (patched below)
        0x00000000,  # 17 nop
        ORI(0, 5, 0x8FE3),  # 18 ori a1, zero, 0x8FE3 (pair hi)
        SLTU(5, 4, 5),  # 19 sltu a1, a1, a0 (hi < vid; catches hi16 != 0)
        0,  # 20 bnez a1, SKIP (patched below)
        0x00000000,  # 21 nop
        SW(17, 4, 8),  # 22 sw a0, 8(s1) (copy +0x04 -> +0x08)
        0,  # 23 SKIP: j RET (patched below)
        0x00000000,  # 24 nop
    ]
    assert len(code) == 25
    A = lambda i: rt + i * 4
    code[12] = BEQ(5, 0, (A(23) - A(12) - 4) // 4)
    code[16] = BNE(5, 0, (A(23) - A(16) - 4) // 4)
    code[20] = BNE(5, 0, (A(23) - A(20) - 4) // 4)
    code[23] = J(ret)
    return code


# gate restore: USA stubbed the replay gate (always returns 0, replay never
# runs). Port JP logic (entry+0x08 != -1 -> 1 else 0). Hook 0xDE5C0 (2 words).
GATE_HOOK_FVA = 0xDE5C0
GATE_HOOK_EXPECT = {}
GATE_CAVE_FVA = CODE_FVA + 468  # 25 words -> ends +568
GATE_RC_FVA = CODE_FVA + 648  # count + entry + entry+0x08 (12B)


def gate_cave():
    rt = GATE_CAVE_FVA + RT
    grc = GATE_RC_FVA + RT
    code = [
        LUI(8, (grc >> 16) & 0xFFFF),  # 0 lui t0, HI(GRC)
        ORI(8, 8, grc & 0xFFFF),  # 1 ori t0, LO(GRC)
        LW(8, 5, 0),  # 2 lw a1, 0(t0) (count)
        ADDIU(5, 5, 1),  # 3 addiu a1, 1
        SW(8, 5, 0),  # 4 sw a1, 0(t0)
        0x3C050001,  # 5 lui a1, 1
        ADDU(4, 5, 5),  # 6 addu a1, a0, a1
        LW(5, 5, 0x96E4),  # 7 lw a1, -0x691C(a1) (selected idx)
        SLL(5, 6, 6),  # 8 sll a2, a1, 6
        ADDU(5, 5, 5),  # 9 addu a1, a1, a1
        ADDU(6, 5, 5),  # 10 addu a1, a2, a1
        SLL(5, 5, 2),  # 11 sll a1, a1, 2
        SUBU(5, 6, 5),  # 12 subu a1, a1, a2
        ADDU(4, 5, 4),  # 13 addu a0, a0, a1
        ADDIU(4, 4, 0xE0),  # 14 addiu a0, a0, 0xE0 (entry)
        SW(8, 4, 4),  # 15 sw a0, 4(t0) (rec entry)
        LW(4, 4, 8),  # 16 lw a0, 8(a0) (entry+0x08)
        SW(8, 4, 8),  # 17 sw a0, 8(t0) (rec +8 value)
        ADDIU(0, 5, 0xFFFF),  # 18 addiu a1, zero, -1
        0,  # 19 beq a0, a1, SKIP (patched below)
        0x00000000,  # 20 nop
        0x03E00008,  # 21 jr ra
        ORI(0, 2, 1),  # 22 ori v0, zero, 1 (delay: return 1)
        0x03E00008,  # 23 SKIP: jr ra
        0x00001025,  # 24 move v0, zero (delay: return 0)
    ]
    assert len(code) == 25
    A = lambda i: rt + i * 4
    code[19] = BEQ(4, 5, (A(23) - A(19) - 4) // 4)
    return code


def replay_cave():
    rt = REPLAY_CAVE_FVA + RT
    rc = REPLAY_RC_FVA + RT
    ret = REPLAY_RET_FVA + RT
    code = [
        0x00808025,  # 0 move s0, a0 (displaced)
        0x3C090000 | ((rc >> 16) & 0xFFFF),  # 1 lui t1, HI(RC)
        ORI(9, 9, rc & 0xFFFF),  # 2 ori t1, LO(RC)
        LW(9, 10, 0),  # 3 lw t2, 0(t1) (count)
        ANDI(10, 10, 7),  # 4 andi t2, t2, 7
        SLL(10, 10, 3),  # 5 sll t2, t2, 3
        ADDU(9, 10, 10),  # 6 addu t2, t1, t2
        SW(10, 18, 4),  # 7 sw s2, 4(t2) (record entry)
        LW(18, 8, 4),  # 8 lw t0, 4(s2) (vid)
        SW(10, 8, 8),  # 9 sw t0, 8(t2) (record vid)
        LW(9, 10, 0),  # 10 lw t2, 0(t1)
        ADDIU(10, 10, 1),  # 11 addiu t2, t2, 1
        SW(9, 10, 0),  # 12 sw t2, 0(t1)
        ADDIU(0, 9, 0xFFFF),  # 13 addiu t1, zero, -1
        0,  # 14 beq t0, t1, SKIP (patched below)
        0x00000000,  # 15 nop
        ORI(0, 9, 0x8C00),  # 16 ori t1, zero, 0x8C00 (pair lo)
        0,  # 17 placeholder (sltu, fixed below)
        0,  # 18 bnez t1, SKIP (patched below)
        0x00000000,  # 19 nop
        ORI(0, 9, 0x8FE3),  # 20 ori t1, zero, 0x8FE3 (pair hi)
        0,  # 21 placeholder (sltu, fixed below)
        0,  # 22 bnez t1, SKIP (patched below)
        0x00000000,  # 23 nop
        0x3C0908A2,  # 24 lui t1, 0x8A2
        0x8D297508,  # 25 lw t1, 0x7508(t1) (global)
        0x25296DA0,  # 26 addiu t1, t1, 0x6DA0 (engine)
        0x8D290030,  # 27 lw t1, 0x30(t1) (voiceobj)
        0xAD28001C,  # 28 sw t0, 0x1C(t1) (store vid)
        SW(18, 8, 8),  # 29 sw t0, 8(s2) (entry+0x08 = vid, JP parity)
        0x8E050010,  # 30 SKIP: lw a1, 0x10(s0) (displaced)
        0,  # 31 j RET (patched below)
        0x00000000,  # 32 nop
    ]
    assert len(code) == 33
    A = lambda i: rt + i * 4
    code[14] = BEQ(8, 9, (A(30) - A(14) - 4) // 4)
    code[17] = SLTU(8, 9, 9)
    code[18] = BNE(9, 0, (A(30) - A(18) - 4) // 4)
    code[21] = SLTU(9, 8, 9)
    code[22] = BNE(9, 0, (A(30) - A(22) - 4) // 4)
    code[31] = J(ret)
    return code


def LUI(rt, imm):
    return (0x0F << 26) | (rt << 16) | (imm & 0xFFFF)


def BNE(rs, rt, imm):
    return (0x05 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def LW(rs, rt, imm):
    return (0x23 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def SW(rs, rt, imm):
    return (0x2B << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def ORI(rs, rt, imm):
    return (0x0D << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def ADDIU(rs, rt, imm):
    return (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def ANDI(rs, rt, imm):
    return (0x0C << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def SLL(rt, rd, sh):
    return (rt << 16) | (rd << 11) | (sh << 6)


def SRL(rt, rd, sh):
    return (rt << 16) | (rd << 11) | (sh << 6) | 2


def ADDU(rs, rt, rd):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x21


def SLTU(rs, rt, rd):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x2B


def SLTIU(rs, rt, imm):
    # sltiu rt, rs, imm  ->  rt = (rs < imm) unsigned. opcode 0x0B (0x0A = slti!)
    return (0x0B << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def SUBU(rs, rt, rd):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x23


def BEQ(rs, rt, imm):
    return (0x04 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def load_entries():
    """Prologue rows plus any post-prologue contexts.

    v3_entries.txt holds the audited prologue table (context c10=38381).
    extra_entries.txt holds later chapters as "c10 key vid", so new chapters
    can be added without touching the bilingual-audited prologue table. The
    walker already compares each entry's c10 against the live context
    (lw 0(t5) vs ctx+0x10), so mixed contexts need no code change.

    Both files are TRACKED build inputs: a missing extra_entries.txt once
    silently produced a table without the chapter-1 row (vid 2287) while the
    verifier - which read the same optional file - still passed.  So its
    absence is now fatal.
    """
    out = []
    with open(os.path.join(v2.WORK, 'v3_entries.txt')) as f:
        for line in f:
            if not line.split() or not line.split()[0].isdigit():
                continue
            key, vid, _ju, _uu = line.split()
            out.append((38381, int(key), int(vid)))
    extra = os.path.join(v2.WORK, 'extra_entries.txt')
    if not os.path.exists(extra):
        raise SystemExit('missing tracked build input: %s (one row per later '
                         'chapter, e.g. "50098 191506 2287"; restore it with '
                         'git checkout <rev>^ -- work/extra_entries.txt)'
                         % extra)
    with open(extra, encoding='utf-8') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3 or not parts[0].isdigit():
                continue
            out.append((int(parts[0]), int(parts[1]), int(parts[2])))
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
    pkl = os.path.join(v2.WORK, 'usa_loader_diff.pkl')
    if not os.path.isfile(pkl):
        raise SystemExit('missing tracked build input: %s (loader-fixup '
                         'address set; restore it with '
                         'git checkout <rev>^ -- work/usa_loader_diff.pkl, '
                         'or re-derive with loader_fixups.py)' % pkl)
    diff = pickle.loads(open(pkl, 'rb').read())
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

    # safety: every written word must be loader-clean file-zero.
    # walker+descr must stay within the first 228B (caves live after it).
    blob = struct.pack('<%dI' % len(code), *code) + struct.pack('<%dI' % len(descr), *descr)
    assert len(blob) <= 228, len(blob)
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

    # backlog-replay voice hook
    for fva, exp in REPLAY_HOOK_EXPECT.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'replay hook word at {fva:#x} = {cur:#x}'
    assert REPLAY_HOOK_FVA not in diff and (REPLAY_HOOK_FVA + 4) not in diff, 'hook hits fixups!'
    # GLOBAL_VAR (file off 0x223508 = GLOBAL_VAR_RT - RT) IS a loader fixup;
    # harmless, because the cave only READS it at runtime, after the loader
    # applied it.  The old assert here checked a typo'd 0x227508 (absent from
    # the diff) and so proved nothing; only patch WRITES must dodge fixups,
    # and those (chunks, hook, caves, recorders) are asserted individually.
    rcave = replay_cave()
    rblob = struct.pack('<%dI' % len(rcave), *rcave)
    roff = SEG + REPLAY_CAVE_FVA
    assert not any(h in diff for h in range(REPLAY_CAVE_FVA, REPLAY_CAVE_FVA + len(rblob), 4)), 'replay cave hits fixups!'
    cur = d[roff:roff + len(rblob)]
    assert all(b == 0 for b in cur), 'replay cave home not zero!'
    d[roff:roff + len(rblob)] = rblob
    d[SEG + REPLAY_HOOK_FVA:SEG + REPLAY_HOOK_FVA + 4] = struct.pack('<I', J(REPLAY_CAVE_FVA + RT))
    d[SEG + REPLAY_HOOK_FVA + 4:SEG + REPLAY_HOOK_FVA + 8] = struct.pack('<I', 0)
    print(f'replay hook: j {REPLAY_CAVE_FVA + RT:#x} at fva {REPLAY_HOOK_FVA:#x}')

    # logger copy hook (+0x04 pair vid -> +0x08 for replay).
    # ROUND-5: hook moved to 0xDDF80; delay slot 0xDDF84 stays NATIVE stock
    # (a branch 0xddf4c->0xddf80 lands there; zeroing it skipped the
    # displaced ori and crashed the game). Only the ori word is replaced.
    for fva, exp in LOG_HOOK_EXPECT.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'log hook word at {fva:#x} = {cur:#x}'
    for fva, exp in LOG_NATIVE.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'log native word at {fva:#x} = {cur:#x}'
    assert LOG_HOOK_FVA not in diff and (LOG_HOOK_FVA + 4) not in diff, 'log hook hits fixups!'
    lcave = log_cave()
    lblob = struct.pack('<%dI' % len(lcave), *lcave)
    assert len(lblob) <= 108, f'log cave exceeds slot: {len(lblob)}'
    loff = SEG + LOG_CAVE_FVA
    assert not any(h in diff for h in range(LOG_CAVE_FVA, LOG_CAVE_FVA + len(lblob), 4)), 'log cave hits fixups!'
    cur = d[loff:loff + len(lblob)]
    assert all(b == 0 for b in cur), 'log cave home not zero!'
    d[loff:loff + len(lblob)] = lblob
    d[SEG + LOG_HOOK_FVA:SEG + LOG_HOOK_FVA + 4] = struct.pack('<I', J(LOG_CAVE_FVA + RT))
    # delay slot + neighbours must still be stock words (never zeroed)
    for fva, exp in LOG_NATIVE.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'log native word at {fva:#x} altered: {cur:#x}'
    assert struct.unpack('<I', d[SEG + LOG_HOOK_FVA:SEG + LOG_HOOK_FVA + 4])[0] == J(LOG_CAVE_FVA + RT)
    print(f'log hook: j {LOG_CAVE_FVA + RT:#x} at fva {LOG_HOOK_FVA:#x} (delay {LOG_HOOK_FVA + 4:#x} native)')

    # gate restore hook (0xDE5C0 stub -> JP logic)
    for fva, exp in {GATE_HOOK_FVA: 0x03E00008, GATE_HOOK_FVA + 4: 0x00001025}.items():
        off = SEG + fva
        cur = struct.unpack('<I', d[off:off + 4])[0]
        assert cur == exp, f'gate word at {fva:#x} = {cur:#x}'
    assert GATE_HOOK_FVA not in diff and (GATE_HOOK_FVA + 4) not in diff, 'gate hook hits fixups!'
    gcave = gate_cave()
    gblob = struct.pack('<%dI' % len(gcave), *gcave)
    goff = SEG + GATE_CAVE_FVA
    assert not any(h in diff for h in range(GATE_CAVE_FVA, GATE_CAVE_FVA + len(gblob), 4)), 'gate cave hits fixups!'
    cur = d[goff:goff + len(gblob)]
    assert all(b == 0 for b in cur), 'gate cave home not zero!'
    d[goff:goff + len(gblob)] = gblob
    d[SEG + GATE_HOOK_FVA:SEG + GATE_HOOK_FVA + 4] = struct.pack('<I', J(GATE_CAVE_FVA + RT))
    d[SEG + GATE_HOOK_FVA + 4:SEG + GATE_HOOK_FVA + 8] = struct.pack('<I', 0)
    print(f'gate hook: j {GATE_CAVE_FVA + RT:#x} at fva {GATE_HOOK_FVA:#x}')

    # flight recorders: layout sanity + zero-init (count must start at 0)
    layout = [
        (REPLAY_CAVE_FVA, len(rcave) * 4),
        (LOG_CAVE_FVA, len(lblob)),
        (GATE_CAVE_FVA, len(gblob)),
        (REPLAY_RC_FVA, 68),
        (LOG_RC_FVA, 12),
        (GATE_RC_FVA, 12),
    ]
    prev_end = CODE_FVA + 228
    for fva, ln in layout:
        assert fva >= prev_end, f'layout overlap at {fva:#x} < {prev_end:#x}'
        prev_end = fva + ln
    assert prev_end <= CODE_FVA + CODE_GAP_LEN, f'gap overflow: {prev_end:#x}'
    for fva, ln in ((REPLAY_RC_FVA, 68), (LOG_RC_FVA, 12), (GATE_RC_FVA, 12)):
        assert not any(h in diff for h in range(fva, fva + ln, 4)), f'recorder {fva:#x} hits fixups!'
        cur = d[SEG + fva:SEG + fva + ln]
        assert all(b == 0 for b in cur), f'recorder {fva:#x} not zero!'
        d[SEG + fva:SEG + fva + ln] = b'\x00' * ln
    print(f'recorders zeroed: RC@{REPLAY_RC_FVA:#x} LOG_RC@{LOG_RC_FVA:#x} GATE_RC@{GATE_RC_FVA:#x}, '
          f'gap used {prev_end - CODE_FVA}/664B')

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
