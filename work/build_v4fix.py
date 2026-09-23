"""Apply voice-mapping corrections (audit v4 PC build) + EBOOT-only rebuild.

Corrections: vid -> (new_key, new_usa_unit). Drops remove entries.
Keys verified against audit USA-prev/next brackets + text dumps.
"""
import shutil
import struct
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
import build_v4
import build_undub_v2 as v2

ENTRIES = r'D:\Documents\Default Project\work\v3_entries.txt'

# vid -> (new_key, new_usa_unit)
MOVES = {
    # prologue cluster (anchors early; true lines verified by content)
    '16': (122610, 23836), '17': (122702, 23844),
    '18': (123440, 23960), '19': (123534, 23970),
    '20': (123624, 23984), '21': (123730, 24019),
    '22': (123836, 24029), '23': (124076, 24061),
    '24': (124136, 24074), '25': (124350, 24111),
    '26': (124434, 24124), '27': (124532, 24132),
    '28': (124750, 24179), '29': (124832, 24187),
    '31': (124962, 24214), '32': (125038, 24224),
    # off-by-one-late blocks (move to USA-prev line)
    '40': (125592, 24634), '41': (125620, 24642), '42': (125674, 24655),
    '116': (131406, 26749), '117': (131468, 26757),
    '119': (131604, 26778),
    '125': (132134, 26839),
    '126': (132188, 26847), '127': (132272, 26855),
}
DROPS = {'30', '118', '124'}


def main():
    shutil.copy(ENTRIES, ENTRIES + '.pre_audit_fix')
    rows = [l.split() for l in open(ENTRIES)]
    print('entries before:', len(rows))
    out = []
    seen_keys = set()
    for r in rows:
        key, vid, ju, uu = r[0], r[1], r[2], r[3]
        if vid in DROPS:
            print(f'  drop vid {vid} (was usa {uu})')
            continue
        if vid in MOVES:
            key, uu = str(MOVES[vid][0]), str(MOVES[vid][1])
            print(f'  move vid {vid}: -> usa {uu} key {key}')
        assert key not in seen_keys, f'duplicate key {key} for vid {vid}!'
        seen_keys.add(key)
        out.append((key, vid, ju, uu))
    print('entries after:', len(out))
    assert len(out) == len(rows) - len(DROPS)
    with open(ENTRIES, 'w') as f:
        for key, vid, ju, uu in out:
            f.write(f'{key} {vid} {ju} {uu}\n')
    print('table rewritten')
    build_v4.make_eboot()
    v2.patch_eboot_extent()
    # verify a moved key landed in the extent
    with open(v2.OUT_ISO, 'rb') as f:
        f.seek(1615 * 2048 + 0xC0 + 0x224868)
        code0 = struct.unpack('<I', f.read(4))[0]
    assert code0 == 0xAFA20008, hex(code0)
    print('EBOOT extent updated + hook verified; ISO ready:', v2.OUT_ISO)


if __name__ == '__main__':
    main()
