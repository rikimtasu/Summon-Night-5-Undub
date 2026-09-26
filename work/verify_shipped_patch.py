# -*- coding: utf-8 -*-
"""Static verifier for the shipped Summon Night 5 undub patch.

Checks everything the voice table depends on, straight from the patched EBOOT -
no emulator, no save files, no network.  This covers ALL chapters at once,
because it verifies the MECHANISM rather than one chapter's script:

  1. engine clamp NOPed      (0x17904/08/0C) - without this every story voice
                              id (< 0x9088) is forced to -1 and nothing plays
  2. story hook installed    (j at 0x17848 + displaced sw at 0x1784C)
  3. walker code intact      (35 words at 0x224868, all immediates re-derived)
  4. chunk descriptors sane  (13 x {runtime addr, count}, inside chunk homes)
  5. table contents EXACTLY equal the reviewed source tables
     (v3_entries.txt + extra_entries.txt), with unique (c10,key) and (c10,vid).
     Both are TRACKED inputs and both are now REQUIRED: extra_entries.txt used
     to be optional, so deleting it silently dropped the chapter-1 row from
     the expectation set - and the verifier, which read the same optional
     file, still passed.  It fails loudly instead.
  6. backlog-replay hooks    (0xDE430, 0xDDF80, 0xDE5C0), their delay slots,
     and stock neighbours
  7. no patched word collides with an EBOOT loader fixup
     (usa_loader_diff.pkl) - the failure that bricked v3.  The written set
     covers walker, descriptors, table chunks, hooks + delay slots, the
     three cave bodies and the three flight recorders.  A MISSING pkl is a
     FAILURE, not a skip: this guard is the one that caught the brick.
  8. shipped cave bodies (replay/log/gate) compared word-for-word against
     a re-derivation, flight recorders zeroed

Every constant is re-derived here from the documented semantics instead of being
imported from the builder, so a builder bug cannot hide behind a shared helper.

Usage
-----
    python verify_shipped_patch.py                       # default ISO
    python verify_shipped_patch.py --root D:\\artifacts    # artifact dir
    python verify_shipped_patch.py --eboot work/EBOOT_USA_patched.bin
    python verify_shipped_patch.py --iso "Summon Night 5 (USA) Undub.iso"
    python verify_shipped_patch.py --xdelta "…Undub.xdelta" \\
        --source-iso "Summon Night 5 (USA).iso"

Paths come from work/paths.py: $SN5_ROOT (default: this checkout) supplies the
ISOs/EBOOTs and its work/ dir supplies the tracked tables, so the tool can be
run from any clone.
"""
import argparse
import hashlib
import os
import pickle
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

WORK = paths.WORK
ROOT = paths.ROOT
# shipped undub ISO, RE_notes.md "CURRENT shipped artifact hashes"
UNDUB_ISO_SHA256 = ('e88acbfb7d76ee1c8a8310c49d4c2be0a1f8896c11f576a022bbef1e3b8309d1')
SEG = 0xC0
RT = 0x08804000

# ---- layout (documented in RE_notes.md; mirrors build_v4.py) --------------
CODE_FVA = 0x224868
HOOK_FVA = 0x17848
RET_FVA = 0x17858
V2_NOPS = {0x17904: 0x0205282B, 0x17908: 0x54A00001, 0x1790C: 0x2410FFFF}
HOOK_STOCK = {0x17848: 0xAFA20008, 0x1784C: 0x02402025}
CHUNK_HOMES = [
    (0x2334F4, 648), (0x22E33C, 496), (0x2242B8, 396), (0x22FEC0, 380),
    (0x2240E4, 380), (0x223C40, 332), (0x22B760, 332), (0x22D164, 332),
    (0x223E30, 304), (0x224F20, 288), (0x22F2F0, 280), (0x224B28, 280),
    (0x22FAFE, 256),
]
REPLAY_HOOK_FVA, REPLAY_HOOK_STOCK = 0xDE430, {0xDE430: 0x00808025,
                                              0xDE434: 0x8E050010}
LOG_HOOK_FVA, LOG_HOOK_STOCK = 0xDDF80, {0xDDF80: 0x34140000}
LOG_NATIVE = {0xDDF7C: 0xAE340014, 0xDDF84: 0x0220A825, 0xDDF88: 0x02912021}
GATE_HOOK_FVA, GATE_HOOK_STOCK = 0xDE5C0, {0xDE5C0: 0x03E00008,
                                          0xDE5C4: 0x00001025}
REPLAY_RET_FVA, LOG_RET_FVA = 0xDE438, 0xDDF88
# gap layout after the walker+descriptors (228B): caves then recorders
REPLAY_CAVE_FVA = CODE_FVA + 228    # 33 words -> +360
LOG_CAVE_FVA = CODE_FVA + 360       # 25 words -> +460 (slot to +468)
GATE_CAVE_FVA = CODE_FVA + 468      # 25 words -> +568
REPLAY_RC_FVA = CODE_FVA + 568      # recorder: count + 8x(entry,vid) = 68B
LOG_RC_FVA = CODE_FVA + 636         # recorder: count + entry + vid = 12B
GATE_RC_FVA = CODE_FVA + 648        # recorder: count + entry + val = 12B
QUEUE_FN_RT = 0x820C + RT
PROLOGUE_C10 = 38381
KNOWN_C10 = (38381, 50098)
ISO_EBOOT_OFF = 0x327800          # absolute ISO byte offset of EBOOT.BIN
EBOOT_SIZE = 3018032

I_SCAN, I_ADV, I_CHUNK, I_DOCALL = 11, 22, 9, 26
A = lambda i: (CODE_FVA + RT) + i * 4


# ------------------------------------------------------------- MIPS helpers
def J(target):
    return 0x08000000 | ((target >> 2) & 0x03FFFFFF)


def BNE(rs, rt, imm):
    return 0x14000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def bne_to(branch_idx, target_idx, rs, rt):
    """BNE at walker word `branch_idx` jumping to word `target_idx`.

    MIPS: target = pc + 4 + imm*4, with pc = walker runtime base + branch*4.
    (Passing the TARGET index where the branch index belongs silently produces
    imm=-1 and a branch into the wrong place - that is what bit the builder.)
    """
    imm = (A(target_idx) - A(branch_idx) - 4) // 4
    return BNE(rs, rt, imm)


def lui_ori(rd, value):
    """(lui, ori) pair materialising `value` in register rd."""
    return (0x3C000000 | (rd << 16) | ((value >> 16) & 0xFFFF),
            0x34000000 | (rd << 21) | (rd << 16) | (value & 0xFFFF))


# generic MIPS encoders used by the cave re-derivations below (opcode forms
# match the documented semantics; build_v4 uses equivalents)
def BEQ(rs, rt, imm):
    return 0x10000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def LUI(rt, imm):
    return 0x3C000000 | (rt << 16) | (imm & 0xFFFF)


def ORI(rs, rt, imm):
    return 0x34000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def LW(rs, rt, imm):
    return 0x8C000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def SW(rs, rt, imm):
    return 0xAC000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def ADDIU(rs, rt, imm):
    return 0x24000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def ANDI(rs, rt, imm):
    return 0x30000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def SLTIU(rs, rt, imm):
    return 0x2C000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def SLL(rt, rd, sh):
    return (rt << 16) | (rd << 11) | (sh << 6)


def ADDU(rs, rt, rd):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x21


def SUBU(rs, rt, rd):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x23


def SLTU(rs, rt, rd):
    return (rs << 21) | (rt << 16) | (rd << 11) | 0x2B


def branch_target(word, pc_rt):
    """Resolve a BNE/BEQ/J word to its runtime target (or None)."""
    op = word >> 26
    if op == 5:                                     # BNE / BEQ
        return (pc_rt + 4 + ((word & 0xFFFF) << 2 if not (word & 0x8000)
                             else ((word & 0xFFFF) - 0x10000) << 2))
    if op == 2:
        return ((pc_rt + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
    return None


def expected_walker(nchunks):
    """Re-derive the 35-word walker from semantics (not from build_v4)."""
    descr_rt = (CODE_FVA + RT) + 35 * 4
    hi, lo = lui_ori(11, descr_rt)                  # t3 = &descriptors
    code = [
        0xAFA20008,                                 # 0  sw   v0, 8(sp)
        0x02402025,                                 # 1  or   a0, s2, zero
        0x8E08001C,                                 # 2  lw   t0, 0x1C(s0) stream
        0x8E090010,                                 # 3  lw   t1, 0x10(s0) c10
        0x8FAA0000,                                 # 4  lw   t2, 0(sp)     p0
        0x01485023,                                 # 5  subu t2, t2, t0    key
        hi, lo,                                     # 6,7 t3 = &descriptors
        0x340C0000 | nchunks,                       # 8  ori  t4, zero, K
        0x8D6D0000,                                 # 9  lw   t5, 0(t3)
        0x8D6E0004,                                 # 10 lw   t6, 4(t3)
        0x8DA20000,                                 # 11 lw   v0, 0(t5)
        0, 0,                                       # 12 bne v0,t1 -> adv
        0x8DA20004,                                 # 14 lw   v0, 4(t5)
        0, 0,                                       # 15 bne v0,t2 -> adv
        0x8DA20008,                                 # 17 lw   v0, 8(t5)
        0x8E4D0030,                                 # 18 lw   t5, 0x30(s2)
        0xADA2001C,                                 # 19 sw   v0, 0x1C(t5)
        0, 0,                                       # 20 j    -> docall
        0x25AD000C,                                 # 22 addiu t5, t5, 12
        0x25CEFFFF,                                 # 23 addiu t6, t6, -1
        0, 0,                                       # 24 bne t6,zero -> scan
        0x256B0008,                                 # 26 addiu t3, t3, 8
        0x258CFFFF,                                 # 27 addiu t4, t4, -1
        0, 0,                                       # 28 bne t4,zero -> chunk
        0x02402021,                                 # 30 move a0, s2
        0x0C000000 | ((QUEUE_FN_RT >> 2) & 0x03FFFFFF),   # 31 jal queue
        0x001D2821,                                 # 32 move a1, sp
        0, 0,                                       # 33 j    -> ret
        0x00000000,                                 # 34 nop
    ]
    imm = lambda i: (A(i) - (A(0) + i * 4) - 4) // 4
    code[12] = bne_to(12, I_ADV, 2, 9)              # bne v0, t1  -> adv
    code[15] = bne_to(15, I_ADV, 2, 10)             # bne v0, t2  -> adv
    code[20] = J(A(I_DOCALL))
    code[24] = bne_to(24, I_SCAN, 14, 0)            # bne t6, zero -> scan
    code[28] = bne_to(28, I_CHUNK, 12, 0)           # bne t4, zero -> chunk
    code[33] = J(RET_FVA + RT)
    return code


def expected_chunks(entries):
    """Re-derive the greedy chunking: entries sorted, homes in order, cap =
    home_len // 12 words.  Returns [(fva, [entries...]), ...]."""
    ordered = sorted(entries)
    chunks, idx = [], 0
    for fva, ln in CHUNK_HOMES:
        cap = ln // 12
        take = ordered[idx:idx + cap]
        if take:
            chunks.append((fva, take))
            idx += len(take)
    if idx != len(ordered):
        raise SystemExit('reviewed entries do not fit the chunk homes')
    return chunks


def expected_replay_cave():
    """Re-derive the 33-word backlog-replay cave (semantics per RE_notes).

    Independent SEMANTIC audit of this code (disasm of branch targets,
    register liveness) lives in work/verify_caves.py; this port exists so
    the SHIPPED bytes can be compared against the intended words here.
    """
    rt = REPLAY_CAVE_FVA + RT
    rc = REPLAY_RC_FVA + RT
    ret = REPLAY_RET_FVA + RT
    code = [
        0x00808025,                              # 0  move s0, a0 (displaced)
        0x3C090000 | ((rc >> 16) & 0xFFFF),      # 1  lui  t1, HI(recorder)
        ORI(9, 9, rc & 0xFFFF),                  # 2  ori  t1, LO(recorder)
        LW(9, 10, 0),                            # 3  lw   t2, 0(t1) count
        ANDI(10, 10, 7),                         # 4  andi t2, 7 (ring)
        SLL(10, 10, 3),                          # 5  sll  t2, 3
        ADDU(9, 10, 10),                         # 6  addu t2, t1, t2
        SW(10, 18, 4),                           # 7  sw   s2, 4(t2) entry
        LW(18, 8, 4),                            # 8  lw   t0, 4(s2) vid
        SW(10, 8, 8),                            # 9  sw   t0, 8(t2) vid
        LW(9, 10, 0),                            # 10 lw   t2, 0(t1)
        ADDIU(10, 10, 1),                        # 11 addiu t2, 1
        SW(9, 10, 0),                            # 12 sw   t2, 0(t1)
        ADDIU(0, 9, 0xFFFF),                     # 13 addiu t1, -1
        0,                                       # 14 beq t0,-1 -> SKIP
        0x00000000,                              # 15 nop
        ORI(0, 9, 0x8C00),                       # 16 ori  t1, 0x8C00 pair lo
        0,                                       # 17 sltu t1, t0, t1
        0,                                       # 18 bnez t1 -> SKIP
        0x00000000,                              # 19 nop
        ORI(0, 9, 0x8FE3),                       # 20 ori  t1, 0x8FE3 pair hi
        0,                                       # 21 sltu t1, t1, t0
        0,                                       # 22 bnez t1 -> SKIP
        0x00000000,                              # 23 nop
        0x3C0908A2,                              # 24 lui  t1, 0x8A2
        0x8D297508,                              # 25 lw   t1, 0x7508(t1)
        0x25296DA0,                              # 26 addiu t1, 0x6DA0
        0x8D290030,                              # 27 lw   t1, 0x30(t1)
        0xAD28001C,                              # 28 sw   t0, 0x1C(t1)
        SW(18, 8, 8),                            # 29 sw   t0, 8(s2) JP parity
        0x8E050010,                              # 30 SKIP: lw a1, 0x10(s0)
        0,                                       # 31 j    RET
        0x00000000,                              # 32 nop
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


def expected_log_cave():
    """Re-derive the 25-word logger copy cave (see verify_caves.py for the
    independent semantic audit)."""
    rt = LOG_CAVE_FVA + RT
    lrc = LOG_RC_FVA + RT
    ret = LOG_RET_FVA + RT
    code = [
        ORI(0, 20, 0),                           # 0  ori s4, zero, 0 (displaced)
        LUI(8, (lrc >> 16) & 0xFFFF),            # 1  lui  t0, HI(recorder)
        ORI(8, 8, lrc & 0xFFFF),                 # 2  ori  t0, LO(recorder)
        SW(8, 17, 4),                            # 3  sw   s1, 4(t0) entry
        LW(17, 4, 4),                            # 4  lw   a0, 4(s1) vid
        SW(8, 4, 8),                             # 5  sw   a0, 8(t0) vid
        LW(8, 5, 0),                             # 6  lw   a1, 0(t0) count
        ADDIU(5, 5, 1),                          # 7  addiu a1, 1
        SW(8, 5, 0),                             # 8  sw   a1, 0(t0)
        LW(17, 5, 8),                            # 9  lw   a1, 8(s1) cur
        ADDIU(5, 5, 1),                          # 10 addiu a1, 1
        SLTIU(5, 5, 2),                          # 11 sltiu a1, 2 empty?
        0,                                       # 12 beqz a1 -> SKIP
        0x00000000,                              # 13 nop
        ORI(0, 5, 0x8C00),                       # 14 ori  a1, 0x8C00 pair lo
        SLTU(4, 5, 5),                           # 15 sltu a1, a0, a1
        0,                                       # 16 bnez a1 -> SKIP
        0x00000000,                              # 17 nop
        ORI(0, 5, 0x8FE3),                       # 18 ori  a1, 0x8FE3 pair hi
        SLTU(5, 4, 5),                           # 19 sltu a1, a1, a0
        0,                                       # 20 bnez a1 -> SKIP
        0x00000000,                              # 21 nop
        SW(17, 4, 8),                            # 22 sw   a0, 8(s1) copy
        0,                                       # 23 SKIP: j RET
        0x00000000,                              # 24 nop
    ]
    assert len(code) == 25
    A = lambda i: rt + i * 4
    code[12] = BEQ(5, 0, (A(23) - A(12) - 4) // 4)
    code[16] = BNE(5, 0, (A(23) - A(16) - 4) // 4)
    code[20] = BNE(5, 0, (A(23) - A(20) - 4) // 4)
    code[23] = J(ret)
    return code


def expected_gate_cave():
    """Re-derive the 25-word replay-gate restore cave (JP logic port)."""
    rt = GATE_CAVE_FVA + RT
    grc = GATE_RC_FVA + RT
    code = [
        LUI(8, (grc >> 16) & 0xFFFF),            # 0  lui  t0, HI(recorder)
        ORI(8, 8, grc & 0xFFFF),                 # 1  ori  t0, LO(recorder)
        LW(8, 5, 0),                             # 2  lw   a1, 0(t0) count
        ADDIU(5, 5, 1),                          # 3  addiu a1, 1
        SW(8, 5, 0),                             # 4  sw   a1, 0(t0)
        0x3C050001,                              # 5  lui  a1, 1
        ADDU(4, 5, 5),                           # 6  addu a1, a0, a1
        LW(5, 5, 0x96E4),                        # 7  lw   a1, -0x691C(a1)
        SLL(5, 6, 6),                            # 8  sll  a2, a1, 6
        ADDU(5, 5, 5),                           # 9  addu a1, a1, a1
        ADDU(6, 5, 5),                           # 10 addu a1, a2, a1
        SLL(5, 5, 2),                            # 11 sll  a1, a1, 2
        SUBU(5, 6, 5),                           # 12 subu a1, a1, a2
        ADDU(4, 5, 4),                           # 13 addu a0, a0, a1
        ADDIU(4, 4, 0xE0),                       # 14 addiu a0, 0xE0 entry
        SW(8, 4, 4),                             # 15 sw   a0, 4(t0) rec
        LW(4, 4, 8),                             # 16 lw   a0, 8(a0) +0x08
        SW(8, 4, 8),                             # 17 sw   a0, 8(t0) rec
        ADDIU(0, 5, 0xFFFF),                     # 18 addiu a1, -1
        0,                                       # 19 beq  a0, a1 -> SKIP
        0x00000000,                              # 20 nop
        0x03E00008,                              # 21 jr   ra (return 1)
        ORI(0, 2, 1),                            # 22 ori  v0, 1 (delay)
        0x03E00008,                              # 23 SKIP: jr ra (return 0)
        0x00001025,                              # 24 move v0, zero (delay)
    ]
    assert len(code) == 25
    A = lambda i: rt + i * 4
    code[19] = BEQ(4, 5, (A(23) - A(19) - 4) // 4)
    return code


# ------------------------------------------------------------------ sources
def read_expected_entries():
    """{(c10, key): vid} from the reviewed source tables.

    Both tables are tracked and both are required: dropping the optional-extra
    file was how the shipped table's chapter-1 row lost its expectation.
    """
    out = {}
    prologue = os.path.join(WORK, 'v3_entries.txt')
    if not os.path.isfile(prologue):
        raise SystemExit('missing tracked table: %s' % prologue)
    with open(prologue) as f:
        for line in f:
            p = line.split()
            if len(p) >= 2 and p[0].isdigit():
                out[(PROLOGUE_C10, int(p[0]))] = int(p[1])
    extra = os.path.join(WORK, 'extra_entries.txt')
    if not os.path.isfile(extra):
        raise SystemExit(
            'missing tracked table: %s (later-chapter rows, e.g. '
            '"50098 191506 2287"; restore with '
            'git checkout <rev>^ -- work/extra_entries.txt).  Without it the '
            'table checks would silently validate a smaller table than the '
            'shipped one.' % extra)
    with open(extra, encoding='utf-8') as f:
        for line in f:
            p = line.split()
            if len(p) >= 3 and p[0].isdigit():
                out[(int(p[0]), int(p[1]))] = int(p[2])
    return out


def _looks_like_eboot(blob):
    if len(blob) < 52 or blob[:4] != b'\x7fELF':
        return False
    phoff = struct.unpack_from('<I', blob, 0x1C)[0]
    if not (0x20 <= phoff < 0x100):
        return False
    ph = struct.unpack_from('<8I', blob, phoff)
    return ph[1] == SEG and ph[2] == 0 and ph[4] > 0x200000


def eboot_from_iso(path):
    if not os.path.isfile(path):
        raise SystemExit('missing ISO: %s\n'
                         'Set SN5_ROOT (or pass --root/--iso) to the directory '
                         'that holds the game artifacts - see work/paths.py.'
                         % path)
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        f.seek(ISO_EBOOT_OFF)
        blob = f.read(EBOOT_SIZE)
        if _looks_like_eboot(blob):
            return blob
        # fall back: scan for the ELF, then read the full extent from there
        f.seek(0)
        step, base = 1 << 22, 0
        while base < min(size, 1 << 31):
            f.seek(base)
            chunk = f.read(step)
            if not chunk:
                break
            s = 0
            while True:
                o = chunk.find(b'\x7fELF', s)
                if o < 0:
                    break
                s = o + 1
                f.seek(base + o)
                cand = f.read(EBOOT_SIZE)
                if _looks_like_eboot(cand):
                    print('EBOOT found at ISO offset 0x%X' % (base + o))
                    return cand
            base += step - 4
    raise SystemExit('could not extract a %d-byte EBOOT from %s'
                     % (EBOOT_SIZE, path))


def find_xdelta3():
    """Locate an xdelta3 binary: $XDELTA3, work/bin/, then PATH.

    The decode is only provenance; correctness comes from the SHA-256 of
    the decoded ISO, so any xdelta3 build works here.  work/bin/ is the
    durable location (the old temp dir got wiped once already) and is
    gitignored - provision: xdelta3 3.2.0 windows-x86_64 release, see
    RE_notes.md.
    """
    cands = []
    env = os.environ.get('XDELTA3')
    if env:
        cands.append(env)
    cands.append(os.path.join(WORK, 'bin', 'xdelta3.exe'))
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return shutil.which('xdelta3')


def eboot_from_xdelta(xd, src_iso):
    exe = find_xdelta3()
    if not exe:
        raise SystemExit(
            'xdelta3 not found; searched $XDELTA3, %s, PATH - see the '
            'xdelta section in work/RE_notes.md'
            % os.path.join(WORK, 'bin', 'xdelta3.exe'))
    print('using xdelta3: %s' % exe, flush=True)
    scratch = tempfile.mkdtemp(prefix='sn5_verify_')
    out = os.path.join(scratch, 'verify_undub_decode.iso')
    print('decoding xdelta -> %s (writes ~1.3 GB, please wait)...' % out,
          flush=True)
    # NOTE: xdelta3 requires the "-d" FLAG form here.  The "d" subcommand
    # form parses "-s" as a filename and dies with
    # "too many filenames: -s".
    subprocess.run([exe, '-d', '-f', '-s', src_iso, xd, out], check=True)
    print('decoded %d bytes' % os.path.getsize(out), flush=True)
    return out, eboot_from_iso(out), scratch


# ------------------------------------------------------------------- checks
class Report(object):
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=''):
        self.rows.append((name, bool(ok), detail))
        print('%-52s %s  %s' % (name, 'PASS' if ok else 'FAIL', detail),
              flush=True)
        return ok

    def skip(self, name, detail=''):
        """Record a SKIP: printed and counted, but not a failure.

        Kept separate from check() so a skip can never masquerade as a PASS,
        and so the summary shows it.  Guards that protect against a shipped
        brick do NOT use this - a missing input for those is a FAIL.
        """
        self.rows.append((name, True, 'SKIP ' + detail))
        print('%-52s %s  %s' % (name, 'SKIP', detail), flush=True)
        return True

    @property
    def failed(self):
        return [r for r in self.rows if not r[1]]

    @property
    def skipped(self):
        return [r for r in self.rows if r[2].startswith('SKIP')]


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', help='artifact directory (default: $SN5_ROOT or '
                                   'this checkout); its work/ dir must hold '
                                   'the tracked tables')
    ap.add_argument('--eboot')
    ap.add_argument('--iso')
    ap.add_argument('--xdelta')
    ap.add_argument('--source-iso')
    args = ap.parse_args(argv)

    global ROOT, WORK
    if args.root:
        ROOT = os.path.abspath(args.root)
        WORK = os.path.join(ROOT, 'work')
    args.iso = args.iso or os.path.join(ROOT,
                                        'Summon Night 5 (USA) Undub.iso')
    args.source_iso = args.source_iso or os.path.join(
        ROOT, 'Summon Night 5 (USA).iso')

    tmp_iso = scratch = None
    if args.xdelta:
        tmp_iso, blob, scratch = eboot_from_xdelta(args.xdelta, args.source_iso)
        src = args.xdelta
    elif args.eboot:
        blob = open(args.eboot, 'rb').read()
        src = args.eboot
    else:
        blob = eboot_from_iso(args.iso)
        src = args.iso

    if src.lower().endswith('.iso'):
        h = hashlib.sha256()
        with open(src, 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''):
                h.update(b)
        print('artifact : %s' % src)
        print('iso sha256: %s' % h.hexdigest())
    else:
        print('artifact : %s' % src)
    print('eboot sha256: %s' % hashlib.sha256(blob).hexdigest())
    print()

    rep = Report()
    u32 = lambda fva: struct.unpack_from('<I', blob, SEG + fva)[0]

    # 0a. decode provenance: a --xdelta run must produce the shipped undub
    # ISO byte-identically.  The EBOOT checks below alone would miss damage
    # in other ISO regions (e.g. the swapped 04.DAT).
    if tmp_iso:
        h = hashlib.sha256()
        with open(tmp_iso, 'rb') as f:
            for b in iter(lambda: f.read(1 << 20), b''):
                h.update(b)
        got = h.hexdigest()
        rep.check('decoded ISO SHA-256 == shipped undub ISO',
                  got == UNDUB_ISO_SHA256, got)

    # 0. ELF sanity
    rep.check('EBOOT is a plain ELF of the expected size',
              blob[:4] == b'\x7fELF' and len(blob) == EBOOT_SIZE,
              '%d bytes' % len(blob))
    phoff = struct.unpack_from('<I', blob, 0x1C)[0]
    ph0 = struct.unpack_from('<8I', blob, phoff)
    rep.check('ELF PH[0] maps file 0xC0 -> vaddr 0',
              ph0[1] == SEG and ph0[2] == 0, 'off=0x%X vaddr=0x%X' % (ph0[1], ph0[2]))

    # stock cross-check, when the stock EBOOT is available
    stock = None
    stock_eboot = os.path.join(ROOT, 'EBOOT_USA_decrypted.bin')
    if os.path.isfile(stock_eboot):
        stock = open(stock_eboot, 'rb').read()
        bad = [hex(f) for f, exp in V2_NOPS.items()
               if struct.unpack_from('<I', stock, SEG + f)[0] != exp]
        rep.check('stock EBOOT has the expected clamp instructions', not bad,
                  'bad: %s' % bad if bad else '3/3 as documented')
    else:
        rep.skip('stock EBOOT has the expected clamp instructions',
                 '%s not found (stock cross-checks need it)' % stock_eboot)

    # 1. clamp NOPed
    left = [hex(f) for f in V2_NOPS if u32(f) != 0]
    rep.check('engine clamp NOPed (0x17904/08/0C)', not left,
              'still live: %s' % left if left else 'all three zero')

    # 2. story hook
    rep.check('story hook is j -> walker',
              u32(HOOK_FVA) == J(CODE_FVA + RT),
              '0x%08X -> 0x%08X (want 0x%08X)'
              % (u32(HOOK_FVA), (u32(HOOK_FVA) << 2) & 0x0FFFFFFF,
                 J(CODE_FVA + RT)))
    rep.check('story hook delay slot holds displaced sw v0,8(sp)',
              u32(HOOK_FVA + 4) == 0xAFA20008, '0x%08X' % u32(HOOK_FVA + 4))
    if stock:
        ok = all(struct.unpack_from('<I', stock, SEG + f)[0] == exp
                 for f, exp in HOOK_STOCK.items())
        rep.check('stock EBOOT had the documented pre-hook words', ok)
    else:
        rep.skip('stock EBOOT had the documented pre-hook words',
                 'stock EBOOT not found')

    # 3. walker
    expect_entries = read_expected_entries()
    chunks = expected_chunks([(c, k, v) for (c, k), v in expect_entries.items()])
    nchunks = len(chunks)
    got = list(struct.unpack_from('<35I', blob, SEG + CODE_FVA))
    want = expected_walker(nchunks)
    mism = [i for i in range(35) if got[i] != want[i]]
    rep.check('walker code (35 words) matches re-derivation', not mism,
              'mismatch at %s' % mism if mism else '35/35')
    for idx, label, target_idx in ((12, 'v0!=c10 -> adv', I_ADV),
                                   (15, 'key!= -> adv', I_ADV),
                                   (20, 'j -> docall', I_DOCALL),
                                   (24, 't6!=0 -> scan', I_SCAN),
                                   (28, 't4!=0 -> chunk', I_CHUNK),
                                   (33, 'j -> ret', None)):
        t = branch_target(got[idx], CODE_FVA + RT + idx * 4)
        if target_idx is None:
            ok = t == (RET_FVA + RT)
            wanttxt = hex(RET_FVA + RT)
        else:
            ok = t == A(target_idx)
            wanttxt = hex(A(target_idx))
        rep.check('walker branch %s lands correctly' % label, ok,
                  '0x%08X (want %s)' % (t or 0, wanttxt))

    # 4. descriptors: must be exactly the independently derived chunking
    dbase = CODE_FVA + 35 * 4
    descr = list(struct.unpack_from('<%dI' % (2 * nchunks), blob, SEG + dbase))
    pairs = [(descr[2 * i], descr[2 * i + 1]) for i in range(nchunks)]
    want_pairs = [((fva + RT) & 0xFFFFFFFF, len(ents)) for fva, ents in chunks]
    rep.check('chunk descriptors match the derived chunking', pairs == want_pairs,
              '%d chunks, %d entries' % (nchunks, sum(c for _a, c in pairs))
              if pairs == want_pairs else
              'got %s want %s' % (pairs[:3], want_pairs[:3]))
    # the word right after the last descriptor must not look like a descriptor
    tail = struct.unpack_from('<I', blob, SEG + dbase + 2 * nchunks * 4)[0]
    homes = {f: ln for f, ln in CHUNK_HOMES}
    ok_addr = all((addr - RT) in homes and cnt * 12 <= homes[addr - RT]
                  for addr, cnt in pairs)
    rep.check('every descriptor points inside a known chunk home', ok_addr,
              'homes used: %d' % len({a - RT for a, _c in pairs}))

    # 5. table contents
    packed = {}
    for (addr, cnt), (fva, _ents) in zip(pairs, chunks):
        off = SEG + (addr - RT)
        for i in range(cnt):
            c10, key, vid = struct.unpack_from('<3I', blob, off + i * 12)
            packed[(c10, key)] = vid
    expect = expect_entries
    rep.check('packed table size == source tables', len(packed) == len(expect),
              'packed %d, source %d' % (len(packed), len(expect)))
    diff = {k: (v, expect.get(k)) for k, v in packed.items() if expect.get(k) != v}
    missing = {k: v for k, v in expect.items() if k not in packed}
    rep.check('every packed triple matches the reviewed table', not diff,
              'mismatched: %s' % list(diff)[:4] if diff else 'all identical')
    rep.check('no reviewed row is missing from the patch', not missing,
              'missing: %s' % list(missing)[:4] if missing else 'none missing')
    dupkey = len(packed) != sum(cnt for _a, cnt in pairs)
    vids = [(c, v) for (c, _k), v in packed.items()]
    rep.check('no duplicate (c10,key)', not dupkey)
    rep.check('no duplicate (c10,vid)', len(vids) == len(set(vids)))
    unknown = sorted({c for c, _k in packed} - set(KNOWN_C10))
    rep.check('all c10 values are known contexts', not unknown,
              'unknown: %s' % unknown if unknown else
              'c10 in %s' % sorted({c for c, _ in packed}))

    # 6. backlog-replay hooks: j -> the EXACT cave, delay slot as designed
    #    (replay/gate delay slots are zeroed by the builder, the log delay
    #    stays native - see LOG_NATIVE)
    for name, fva, stockmap, cave, delay in (
            ('replay', REPLAY_HOOK_FVA, REPLAY_HOOK_STOCK, REPLAY_CAVE_FVA, 0),
            ('log', LOG_HOOK_FVA, LOG_HOOK_STOCK, LOG_CAVE_FVA, 0x0220A825),
            ('gate', GATE_HOOK_FVA, GATE_HOOK_STOCK, GATE_CAVE_FVA, 0)):
        w = u32(fva)
        want = J(cave + RT)
        rep.check('backlog %s hook is j -> its cave' % name, w == want,
                  '0x%08X -> 0x%08X (want 0x%08X)'
                  % (w, (w << 2) & 0x0FFFFFFF, want))
        d = u32(fva + 4)
        rep.check('backlog %s hook delay slot word as designed' % name,
                  d == delay, '0x%08X (want 0x%08X)' % (d, delay))
        if stock:
            bad = [hex(f) for f, exp in stockmap.items()
                   if struct.unpack_from('<I', stock, SEG + f)[0] != exp]
            rep.check('stock EBOOT had the documented %s pre-hook words' % name,
                      not bad, 'bad: %s' % bad if bad else 'as documented')
        else:
            rep.skip('stock EBOOT had the documented %s pre-hook words' % name,
                     'stock EBOOT not found')
    bad = [hex(f) for f, exp in LOG_NATIVE.items() if u32(f) != exp]
    rep.check('stock logger neighbour words still native', not bad,
              'bad: %s' % bad if bad else '3/3 intact')

    # 6b. shipped cave bodies + flight recorders (the generator audit in
    #     verify_caves.py never looks at the shipped bytes)
    caves = (('replay', REPLAY_CAVE_FVA, expected_replay_cave),
             ('log', LOG_CAVE_FVA, expected_log_cave),
             ('gate', GATE_CAVE_FVA, expected_gate_cave))
    cave_words = []
    for name, fva, gen in caves:
        want = gen()
        cave_words.append((fva, len(want)))
        gotw = list(struct.unpack_from('<%dI' % len(want), blob, SEG + fva))
        mism = [i for i in range(len(want)) if gotw[i] != want[i]]
        rep.check('shipped %s cave matches re-derivation' % name, not mism,
                  'mismatch at word %s' % mism if mism else
                  '%d/%d words exact' % (len(want), len(want)))
    for name, fva, ln in (('replay', REPLAY_RC_FVA, 68),
                          ('log', LOG_RC_FVA, 12),
                          ('gate', GATE_RC_FVA, 12)):
        raw = blob[SEG + fva:SEG + fva + ln]
        rep.check('shipped %s flight recorder zeroed' % name,
                  len(raw) == ln and not any(raw),
                  '%d bytes at 0x%X' % (ln, fva))

    # 7. loader fixup collisions
    pkl = os.path.join(WORK, 'usa_loader_diff.pkl')
    if os.path.isfile(pkl):
        diffset = pickle.loads(open(pkl, 'rb').read())
        written = set()
        written.update(range(CODE_FVA, CODE_FVA + 35 * 4, 4))
        written.update(range(dbase, dbase + len(descr) * 4, 4))
        written.update([HOOK_FVA, HOOK_FVA + 4, REPLAY_HOOK_FVA,
                        REPLAY_HOOK_FVA + 4, LOG_HOOK_FVA, GATE_HOOK_FVA,
                        GATE_HOOK_FVA + 4])       # log delay stays native
        for (addr, cnt), (fva, _ents) in zip(pairs, chunks):
            written.update(range(fva, fva + cnt * 12, 4))
        for fva, nwords in cave_words:            # cave bodies (6b)
            written.update(range(fva, fva + nwords * 4, 4))
        for fva, ln in ((REPLAY_RC_FVA, 68), (LOG_RC_FVA, 12),
                        (GATE_RC_FVA, 12)):       # flight recorders
            written.update(range(fva, fva + ln, 4))
        clash = sorted(written & set(diffset))
        rep.check('no patched word collides with an EBOOT loader fixup',
                  not clash, 'clash: %s' % [hex(c) for c in clash[:4]]
                  if clash else '%d words checked' % len(written))
    else:
        # NOT a skip: this guard is the one that caught the v3 brick, so its
        # absence must fail the run (it used to print SKIP and stay green).
        rep.check('no patched word collides with an EBOOT loader fixup', False,
                  'REQUIRED input missing: %s (restore with git checkout '
                  '<rev>^ -- work/usa_loader_diff.pkl)' % pkl)

    print()
    if rep.failed:
        print('%d CHECK(S) FAILED: %s' % (len(rep.failed),
                                         ', '.join(r[0] for r in rep.failed)))
    else:
        print('ALL %d CHECKS PASSED - the patch mechanism is intact for '
              'every chapter.' % len(rep.rows))
    if rep.skipped:
        print('%d SKIPPED (printed above; not failures)' % len(rep.skipped))
    if scratch:
        shutil.rmtree(scratch, ignore_errors=True)
    return 1 if rep.failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
