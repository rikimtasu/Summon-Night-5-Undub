import struct
import re
import sys
sys.path.insert(0, r'D:\Documents\Default Project\work')
from build_v4 import (replay_cave, log_cave, gate_cave,
                      REPLAY_CAVE_FVA, LOG_CAVE_FVA, GATE_CAVE_FVA,
                      REPLAY_RC_FVA, LOG_RC_FVA, GATE_RC_FVA,
                      REPLAY_RET_FVA, LOG_RET_FVA, CODE_FVA, CODE_GAP_LEN, RT,
                      LOG_HOOK_FVA, LOG_NATIVE, REPLAY_HOOK_FVA, GATE_HOOK_FVA,
                      SRC_EBOOT, SEG)
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)


def check(name, code, base, branches, jumps):
    """branches: {idx: target_idx}; jumps: {idx: abs_runtime_target}"""
    blob = struct.pack('<%dI' % len(code), *code)
    insns = list(md.disasm(blob, base))
    assert len(insns) == len(code), (name, len(insns), len(code))
    ok = True
    for idx, t in branches.items():
        ins = insns[idx]
        want = base + t * 4
        got = int(ins.op_str.split(',')[-1].strip(), 16)
        flag = 'OK' if got == want else 'FAIL'
        ok &= got == want
        print('  [%d] %s %s -> %s (want %s) %s' % (idx, ins.mnemonic, ins.op_str, hex(got), hex(want), flag))
    for idx, want in jumps.items():
        ins = insns[idx]
        got = int(ins.op_str.strip(), 16)
        flag = 'OK' if got == want else 'FAIL'
        ok &= got == want
        print('  [%d] %s %s -> %s (want %s) %s' % (idx, ins.mnemonic, ins.op_str, hex(got), hex(want), flag))
    print(name, 'BRANCHES', 'OK' if ok else 'BROKEN')
    return ok


print('== replay cave (33w): beq/skip targets + j RET + entry+8 store')
rcode = replay_cave()
assert len(rcode) == 33
rok = check('replay', rcode, REPLAY_CAVE_FVA + RT,
            {14: 30, 18: 30, 22: 30}, {31: REPLAY_RET_FVA + RT})
print('== log cave (25w): 3 skips -> 23 + j RET(0xDDF88)')
lcode = log_cave()
assert len(lcode) == 25
lok = check('log', lcode, LOG_CAVE_FVA + RT,
            {12: 23, 16: 23, 20: 23}, {23: 0xDDF88 + RT})
print('== gate cave (25w): beq -> 2nd jr, both jr ra present, sel-offset 0x96E4')
gcode = gate_cave()
assert len(gcode) == 25
gins = list(md.disasm(struct.pack('<%dI' % len(gcode), *gcode), GATE_CAVE_FVA + RT))
gok = check('gate', gcode, GATE_CAVE_FVA + RT, {19: 23}, {})
jrs = [i.address for i in gins if i.mnemonic == 'jr']
assert len(jrs) == 2, jrs
print('  gate: 2 jr ra present, sel read imm = 0x96E4 checked below')

# register-sanity spot checks (against disasm text, not hand math)
g_txt = [(i.mnemonic, i.op_str) for i in
         md.disasm(struct.pack('<%dI' % len(rcode), *rcode), REPLAY_CAVE_FVA + RT)]
l_txt = [(i.mnemonic, i.op_str) for i in
         md.disasm(struct.pack('<%dI' % len(lcode), *lcode), LOG_CAVE_FVA + RT)]
gt_txt = [(i.mnemonic, i.op_str) for i in gins]
assert g_txt[29] == ('sw', '$t0, 8($s2)'), g_txt[29]
assert g_txt[28] == ('sw', '$t0, 0x1c($t1)'), g_txt[28]
assert l_txt[0] == ('ori', '$s4, $zero, 0'), l_txt[0]  # displaced ori (round-5)
assert l_txt[3] == ('sw', '$s1, 4($t0)'), l_txt[3]     # rec entry
assert l_txt[4] == ('lw', '$a0, 4($s1)'), l_txt[4]     # vid at fire
assert l_txt[5] == ('sw', '$a0, 8($t0)'), l_txt[5]     # rec vid
assert l_txt[9] == ('lw', '$a1, 8($s1)'), l_txt[9]     # cur +0x08
assert l_txt[11] == ('sltiu', '$a1, $a1, 2'), l_txt[11]  # empty = {0,-1}
assert l_txt[15] == ('sltu', '$a1, $a0, $a1'), l_txt[15]  # vid >= 0x8C00
assert l_txt[19] == ('sltu', '$a1, $a1, $a0'), l_txt[19]  # vid <= 0x8FE3
assert l_txt[22] == ('sw', '$a0, 8($s1)'), l_txt[22]   # copy
assert gt_txt[15] == ('sw', '$a0, 4($t0)'), gt_txt[15]
assert gt_txt[17] == ('sw', '$a0, 8($t0)'), gt_txt[17]
assert gt_txt[7] == ('lw', '$a1, -0x691c($a1)'), gt_txt[7]  # selected idx

# ---- full-text incoming-branch audit (round-5 crash class) ----------------
# A branch landing on a hook's delay slot skips the j -> cave never runs and
# displaced instructions are lost (that is what crashed the game at
# 0x11bd63c5). Disas the WHOLE base text, collect every branch/jump target.
print('== incoming-branch audit (base EBOOT, whole text)')
BR = {'beq', 'bne', 'beql', 'bnel', 'bgez', 'bgezal', 'bgezl', 'bgtz', 'bgtzl',
      'blez', 'blezl', 'bltz', 'bltzal', 'bltzl', 'b', 'beqz', 'bnez'}
base = open(SRC_EBOOT, 'rb').read()
incoming = {}
for insn in md.disasm(base[SEG:], 0):
    if insn.mnemonic in BR or insn.mnemonic in ('j', 'jal'):
        m = re.search(r'0x([0-9a-f]+)\s*$', insn.op_str)
        if m:
            incoming.setdefault(int(m.group(1), 16), []).append(
                (insn.address, insn.mnemonic))
# log hook: j@0xDDF80, delay 0xDDF84 must be branch-free, ret 0xDDF88
assert incoming.get(0xDDF84) is None, f'delay 0xDDF84 has branches: {incoming.get(0xDDF84)}'
assert [(hex(s), m) for (s, m) in incoming.get(0xDDF80, [])] == [('0xddf4c', 'beqz')], \
    incoming.get(0xDDF80)  # the known first-render branch: lands ON the j -> cave runs
# replay hook: j@0xDE430 delay 0xDE434 ret 0xDE438 -- fully branch-free
for a in (0xDE430, 0xDE434, 0xDE438):
    assert a not in incoming, f'replay hook {a:#x} has incoming: {incoming[a]}'
# gate hook: jal only may land on 0xDE5C0 (function entry -> hits the j);
# delay 0xDE5C4 must be branch-free
assert all(m == 'jal' for (s, m) in incoming.get(0xDE5C0, [])), \
    incoming.get(0xDE5C0)  # all callers jal -> land on the j -> cave handles
assert incoming.get(0xDE5C4) is None, incoming.get(0xDE5C4)
# stock neighbours of the log hook stay native
for fva, exp in LOG_NATIVE.items():
    cur = struct.unpack('<I', base[SEG + fva:SEG + fva + 4])[0]
    assert cur == exp, f'base word {fva:#x} = {cur:#x} != {exp:#x}'
print('  audit OK: log delay branch-free, replay branch-free, gate jal-only')

# layout: no overlap, fits the 664B gap after the 228B walker/descrip
segs = [(REPLAY_CAVE_FVA, len(rcode) * 4), (LOG_CAVE_FVA, len(lcode) * 4),
        (GATE_CAVE_FVA, len(gcode) * 4), (REPLAY_RC_FVA, 68),
        (LOG_RC_FVA, 12), (GATE_RC_FVA, 12)]
prev = CODE_FVA + 228
for fva, ln in segs:
    assert fva >= prev, (hex(fva), hex(prev))
    prev = fva + ln
assert prev <= CODE_FVA + CODE_GAP_LEN, hex(prev)
print('layout OK: ends at gap+%d/664' % (prev - CODE_FVA))

print('ALL', 'PASS' if (rok and lok and gok) else 'FAIL')
for name, code in (('replay', rcode), ('log', lcode), ('gate', gcode)):
    base = {'replay': REPLAY_CAVE_FVA, 'log': LOG_CAVE_FVA, 'gate': GATE_CAVE_FVA}[name] + RT
    print('----', name, hex(base))
    for insn in md.disasm(struct.pack('<%dI' % len(code), *code), base):
        print('   ', hex(insn.address), insn.mnemonic, insn.op_str)
