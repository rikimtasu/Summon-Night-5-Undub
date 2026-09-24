"""Round-6 prologue voice-mapping corrections + EBOOT-only rebuild.

Ground truth: manual JP<->USA line-by-line alignment (align_dump.txt,
prologue_audit_full.txt). Every target key validated as a real USA text
call with the expected unit before touching the table.

  MOVES: vid -> (new_key, new_usa_unit)
  DROPS: vids whose JP line has no standalone USA counterpart
  ADDS : vid -> (key, jp_unit, usa_unit)  (round-4 drops 30/118/124 reinstated)
"""
import os
import shutil
import struct
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_v4
import build_undub_v2 as v2
from disasm_align import disasm

ENTRIES = r'D:\Documents\Default Project\work\v3_entries.txt'
USA_RAM = r'D:\Documents\Default Project\work\psp_ram_usa3.bin'
USA_BASE = 0x08D68000
USA_SIZE = 158152

# --- the fixes -------------------------------------------------------------
MOVES = {
    # ghift-globs cluster: vids 53-57 each attached one USA line late
    '53': (126792, 24958), '54': (126890, 24972),
    '55': (126984, 24995), '56': (126992, 25030),
    '57': (127062, 25038),
    # v123 ヤレヤレ -> "Oh, dear. I was afraid..." (v122's line; v122 merged/dropped)
    '123': (131992, 26810),
    # v128/129 one line late (UNATT 132350 / USA 132426 are their true lines)
    '128': (132350, 26863), '129': (132426, 26871),
    # branch A: USA order [topic, apology] vs JP [apology, topic] -> swap
    '151': (138586, 29095), '152': (138522, 29085),
    # v349 death-possibility line = UNATT "immediate death" (149904 is an inserted joke)
    '349': (149978, 33583),
    # v416 statement / v417 question each one line late
    '416': (153440, 35223), '417': (153514, 35236),
}
DROPS = {'122'}  # カッコつけた手前 = merged into USA121's line (already has v121)
ADDS = {
    '30': (124914, 26188, 24200),    # 暗すぎるな/あいつを呼ぶか -> "...helping hand from my favorite Cross."
    '118': (131522, 29350, 26770),   # ド根性ってヤツさ -> "master of the backhanded compliment"
    '124': (132050, 29446, 26829),   # ギフトも、フォルス君も -> "Ghift and Folth are trusting me"
}
# old (vid,key) pairs that must NOT exist afterwards / new ones that must
PRESENT = [(124914, 30), (131522, 118), (132050, 124), (126792, 53),
           (126890, 54), (131992, 123), (132350, 128), (132426, 129),
           (138522, 152), (138586, 151), (149978, 349), (153440, 416),
           (153514, 417)]
ABSENT = [(131992, 122), (132050, 123), (132490, 129), (127098, 57),
          (126890, 53), (149904, 349), (153514, 416), (153540, 417),
          (138522, 151), (138586, 152)]


def usa_text_calls():
    """{key: set(units)} for every USA CALL195 text call."""
    ram = open(USA_RAM, 'rb').read()
    blk = ram[USA_BASE - 0x08000000:USA_BASE - 0x08000000 + USA_SIZE]
    c10 = struct.unpack('<I', blk[16:20])[0]
    toks = disasm(blk[:c10 * 2], 12)
    out = {}
    for k, t in enumerate(toks):
        if t[1] == 52 and t[2] == 1 and t[4] and t[4][0] == 195 and k >= 1:
            p = toks[k - 1]
            if p[1] == 50 and p[2] == 5 and p[4]:
                key = 2 * (c10 + p[4][0])
                out.setdefault(key, set()).add(t[0])
    return out


def main():
    calls = usa_text_calls()

    # 1. validate every target key/unit against the USA script
    for vid, (key, uu) in MOVES.items():
        assert key in calls, f'move target key {key} (vid {vid}) is not a USA text call'
        assert uu in calls[key], f'move vid {vid}: unit {uu} not a call site of key {key} ({calls[key]})'
    for vid, (key, ju, uu) in ADDS.items():
        assert key in calls, f'add target key {key} (vid {vid}) is not a USA text call'
        assert uu in calls[key], f'add vid {vid}: unit {uu} not a call site of key {key} ({calls[key]})'
        assert not (key in {m[0] for m in MOVES.values()}), f'add key {key} collides with a move target'
    print(f'validated {len(MOVES)} move + {len(ADDS)} add targets against USA script')

    # 2. transform the table
    backup = ENTRIES + '.pre_round6'
    if os.path.exists(backup):
        # Never clobber a pristine backup: on a re-run the row-level
        # asserts below (add collision) fire AFTER this point, so an
        # unconditional copy would destroy the backup and then die.
        raise SystemExit(f'{backup} already exists - table already has '
                         'round-6 applied? remove it only if you really '
                         'want a fresh backup of the current table')
    shutil.copy(ENTRIES, backup)
    rows = [l.split() for l in open(ENTRIES)]
    print('entries before:', len(rows))
    out, seen_keys, seen_vids = [], set(), set()
    for r in rows:
        key, vid, ju, uu = r
        if vid in DROPS:
            print(f'  drop vid {vid} (was key {key})')
            continue
        if vid in MOVES:
            old = key
            key, uu = str(MOVES[vid][0]), str(MOVES[vid][1])
            print(f'  move vid {vid}: key {old} -> {key} (usa {uu})')
        assert key not in seen_keys, f'duplicate key {key} for vid {vid}'
        assert vid not in seen_vids, f'duplicate vid {vid}'
        seen_keys.add(key)
        seen_vids.add(vid)
        out.append((key, vid, ju, uu))
    for vid in sorted(ADDS, key=int):
        key, ju, uu = (str(x) for x in ADDS[vid])
        assert key not in seen_keys and vid not in seen_vids, f'add collision {vid}/{key}'
        seen_keys.add(key)
        seen_vids.add(vid)
        out.append((key, vid, ju, uu))
        print(f'  add  vid {vid}: key {key} (jp {ju}, usa {uu})')
    out.sort(key=lambda e: int(e[0]))
    assert len(out) == len(rows) - len(DROPS) + len(ADDS), 'row count mismatch'
    assert len(seen_keys) == len(out) and len(seen_vids) == len(out), 'uniqueness broken'
    with open(ENTRIES, 'w') as f:
        for key, vid, ju, uu in out:
            f.write(f'{key} {vid} {ju} {uu}\n')
    print('entries after:', len(out), '- table rewritten')

    # 3. EBOOT-only rebuild + ISO extent patch (v5 opening untouched)
    build_v4.make_eboot()
    v2.patch_eboot_extent()

    # 4. verify: walker word + every fix landed in the packed table
    with open(v2.OUT_ISO, 'rb') as f:
        f.seek(1615 * 2048 + 0xC0 + 0x224868)
        code0 = struct.unpack('<I', f.read(4))[0]
        assert code0 == 0xAFA20008, hex(code0)
        f.seek(1615 * 2048)
        elf = f.read(3018032)
    for key, vid in PRESENT:
        pat = struct.pack('<III', 38381, key, vid)
        assert pat in elf, f'entry (key {key}, vid {vid}) missing from packed table'
    for key, vid in ABSENT:
        pat = struct.pack('<III', 38381, key, vid)
        assert pat not in elf, f'stale entry (key {key}, vid {vid}) still in table'
    print(f'verified {len(PRESENT)} present + {len(ABSENT)} absent entries in extent')
    print('ISO ready:', v2.OUT_ISO)


if __name__ == '__main__':
    main()
