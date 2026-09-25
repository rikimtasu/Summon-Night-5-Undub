# -*- coding: utf-8 -*-
"""Per-chapter voice-trigger coverage census for the SN5 undub patch table.

WHY THIS EXISTS
---------------
The undub does NOT ship a full JP->USA voice map.  The USA script was stripped
in two independent ways (RE_notes.md "Story-voice strip mechanism"):

  * pair-id sites  (op50 f1=4, ids 36000..36835) were NOT deleted from the USA
    script, so they fire natively once the engine clamp at 0x17904 is NOPed.
  * const / f2-1 sites (small ids) WERE deleted together with their arg push.
    The patch table re-injects those by matching (live c10, line byte-offset).

So the table must contain exactly the JP voice sites the USA script deleted,
per chapter, and each row's key must point at the USA line that actually
corresponds to the JP line that vid speaks.  This tool measures the first
requirement offline and prepares the data for the second.

WHAT IT DOES
------------
1. Scans RAM dumps / PPSSPP save states for story script blocks
   (header magic 0x10000201 / 0x10000002) - same invariants as
   scan_all_blocks.py.
2. Classifies every CALL214 voice site as const / f2-1 / pair, per block
   (same census rule as scan_all_blocks.py).
3. Pairs JP and USA blocks into chapters (by voice-id range, which is
   chapter-partitioned with zero overlap), or via --pair.
4. deleted = JP multiset - USA multiset, per kind, using Counter arithmetic so
   duplicate ids cannot hide a hole.
5. Compares the deleted set against the rows the build actually ships
   (v3_entries.txt + extra_entries.txt, same loader as build_v4.load_entries).
6. Validates every shipped row's key against the USA block's real CALL195
   text sites.
7. Emits a bilingual TSV for the human audit that remains the ground truth:
   JP line that vid speaks vs the USA line the key is attached to.

Usage
-----
    python chapter_voice_census.py                 # census + bilingual TSV
    python chapter_voice_census.py --selftest      # assert known-good numbers
    python chapter_voice_census.py --ram-jp a.bin --ram-usa b.bin
    python chapter_voice_census.py --states D:\\...\\PPSSPP_STATE
    python chapter_voice_census.py --pair 43032=38381,55506=50098

Outputs (work/):
    voice_census_report.txt   human-readable census
    voice_bilingual.tsv       JP line vs USA line per vid, for review
"""
import collections
import glob
import os
import struct
import sys

sys.path.insert(0, r'D:\Documents\Default Project\work')
from disasm_align import disasm

WORK = r'D:\Documents\Default Project\work'
PROLOGUE_C10_USA = 38381          # build_v4.load_entries stamps this on v3 rows
V3_ENTRIES = os.path.join(WORK, 'v3_entries.txt')
EXTRA_ENTRIES = os.path.join(WORK, 'extra_entries.txt')
REPORT = os.path.join(WORK, 'voice_census_report.txt')
TSV = os.path.join(WORK, 'voice_bilingual.tsv')

# 11.DAT stores every story script block expanded, header included
# (136 header pairs per version), so a RAM capture is NOT required per chapter.
SCRIPT_DAT = {
    'jp': os.path.join(WORK, 'JP', 'PSP_GAME', 'USRDIR', '11.DAT'),
    'usa': os.path.join(WORK, 'USA', 'PSP_GAME', 'USRDIR', '11.DAT'),
}

# KNOWN_DROPS was {122: 'JP line merged into USA 121 (round-6 drop)'} until
# 2026-09-25, when playtesting + the Gaudi retreat-exchange audit proved the
# round-6 merge theory wrong: vid 122 (カッコつけた手前もあるし、さ) is the
# true voice of USA 131892 ("my stock will go up..."), reinstated. Empty now;
# any future drop must be re-justified here, not silently assumed.
KNOWN_DROPS = {}

# known-good chapters, used by --selftest and for labels
KNOWN = {
    (43032, 38381): 'prologue (shipped: 339 rows)',
    (55506, 50098): 'ch.1 (shipped: 1 row)',
}


# ---------------------------------------------------------------- RAM input
def extract_ram(path):
    """Return a 32 MB RAM image from a raw dump or a zstd .ppst save state."""
    d = open(path, 'rb').read()
    if len(d) == 32 * 1024 * 1024:
        return d                                    # already a raw RAM image
    import zstandard
    rev, comp, esize, usize = struct.unpack('<4I', d[:16])
    out = zstandard.ZstdDecompressor().decompress(
        d[176:176 + esize], max_output_size=usize + 16)
    assert out[0x28:0x28 + 6] == b'Memory', 'not a PPSSPP memory state'
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


# ------------------------------------------------------------ block parsing
def dialect(toks):
    """Find this block's text-call and voice-call targets.

    Call targets are NOT stable across chapters: the prologue uses CALL195
    (text) / CALL214 (voice), chapter 1 onwards uses CALL234 / CALL253.  The
    push idioms in front of them are stable, so pick the targets by shape:

      text call  = target preceded by the most op50 f1=5 string-address pushes
      voice call = target preceded by the most op50 f1=4 pair-id pushes
                   (the rule already established for the prologue)

    Hardcoding 195/214 silently rejects every later chapter; keying on the push
    alone without the target over-counts, because other handlers share pushes.
    """
    counts = collections.defaultdict(collections.Counter)
    for k, t in enumerate(toks):
        if t[1] == 52 and t[2] == 1 and t[4] and k >= 1:
            p = toks[k - 1]
            if p[1] != 50:
                continue
            if p[2] == 5 and p[4]:
                counts[t[4][0]]['f5'] += 1
            elif p[2] == 4 and p[4]:
                counts[t[4][0]]['f4'] += 1
            elif p[2] == 10 and p[4]:
                counts[t[4][0]]['f10'] += 1
            elif p[2] == 11:
                counts[t[4][0]]['f11'] += 1
    if not counts:
        return 0, 0, counts
    text_call = max(counts, key=lambda c: (counts[c]['f5'], counts[c]['f4']))
    voice_call = max(counts, key=lambda c: (counts[c]['f4'], counts[c]['f10']))
    return text_call, voice_call, counts


def census_voice(toks, voice_call):
    """{(kind, id): count} for voice sites in this block's dialect."""
    c = collections.Counter()
    for k, t in enumerate(toks):
        if t[1] == 52 and t[2] == 1 and t[4] and k >= 1 \
                and t[4][0] == voice_call:
            p = toks[k - 1]
            if p[1] != 50:
                continue
            if p[2] == 10 and p[4]:
                c[('const', p[4][0])] += 1
            elif p[2] == 11:
                c[('f2', p[3] - 1)] += 1
            elif p[2] == 4 and p[4]:
                c[('pair', p[4][0])] += 1
    return c


def parse_block(ram, off):
    """Validate one candidate block at `off`; return a block dict or None."""
    if struct.unpack('<I', ram[off + 4:off + 8])[0] != 0x10000002:
        return None
    size = struct.unpack('<I', ram[off + 8:off + 12])[0]
    c10 = struct.unpack('<I', ram[off + 16:off + 20])[0]
    if size & 1 or not (c10 * 2 <= size <= 0xC0000) or not (512 < c10 < 0x40000):
        return None
    if off + size > len(ram):
        return None
    try:
        toks = disasm(ram[off:off + c10 * 2], 12)
    except (IndexError, struct.error):
        return None
    if not toks or not (c10 - 4 <= toks[-1][0] + 1 <= c10):
        return None

    text_call, voice_call, _counts = dialect(toks)
    lines, voices = [], []          # (unit, key) / (unit, kind, id, calltgt)
    for k, t in enumerate(toks):
        if t[1] != 52 or t[2] != 1 or not t[4] or k < 1:
            continue
        tgt = t[4][0]
        p = toks[k - 1]
        if p[1] != 50:
            continue
        # text line: string-address push (op50 f1=5) then the text call
        if tgt == text_call and p[2] == 5 and p[4]:
            lines.append((t[0], 2 * (c10 + p[4][0])))
        elif tgt == voice_call and p[2] == 10 and p[4]:
            voices.append((t[0], 'const', p[4][0], tgt))
        elif tgt == voice_call and p[2] == 11:
            voices.append((t[0], 'f2', p[3] - 1, tgt))
        elif tgt == voice_call and p[2] == 4 and p[4]:
            voices.append((t[0], 'pair', p[4][0], tgt))
    if len(lines) < 5:
        return None
    return {
        'c10': c10, 'size': size, 'off': off,
        'data': ram[off:off + size],
        'lines': lines, 'voices': voices,
        'census': census_voice(toks, voice_call),
        'text_call': text_call, 'voice_call': voice_call,
        'tag': None, 'src': None,
    }


def block_lang(blk):
    """Guess the script's language from its string pool: JP dialogue is mostly
    multi-byte UTF-8, USA dialogue is ASCII.  Lets us tag blocks by CONTENT so
    every psp_ram_*.bin can be used regardless of what it was named."""
    pool = blk['data'][blk['c10'] * 2: blk['c10'] * 2 + 8192]
    if not pool:
        return 'jp'
    high = sum(1 for b in pool if b >= 0x80)
    low = sum(1 for b in pool if 0x20 <= b < 0x7F)
    return 'jp' if high * 3 > low else 'usa'


def scan_ram(ram, tag, src, seen, found):
    magic = struct.pack('<I', 0x10000201)
    start = 0
    while True:
        o = ram.find(magic, start, len(ram) - 32)
        if o < 0:
            break
        start = o + 4
        blk = parse_block(ram, o)
        if blk is None:
            continue
        blk['tag'] = tag or block_lang(blk)
        tagkey = (blk['tag'], blk['c10'], blk['size'],
                  hash(blk['data'][:4096]) & 0xFFFFFFFF)
        if tagkey in seen:
            continue
        seen.add(tagkey)
        blk['src'] = src
        found.append(blk)


def load_generic(paths, seen, found, log):
    """Scan RAM dumps and tag each block by CONTENT (jp/usa), so oddly named
    dumps (replay/crash/backlog/xreplay/1014/title/probe) still contribute."""
    for path in paths:
        try:
            ram = extract_ram(path)
        except Exception as exc:                       # noqa: BLE001
            log.append('  %-34s LOAD FAIL: %s' % (os.path.basename(path), exc))
            continue
        before = len(found)
        scan_ram(ram, None, path, seen, found)
        log.append('  %-34s %d new block(s)' % (os.path.basename(path),
                                                len(found) - before))
        del ram


def load_raw(paths, tag, seen, found, log):
    """Scan a container file (e.g. 11.DAT) for expanded script blocks."""
    for path in paths:
        try:
            blob = open(path, 'rb').read()
        except (IOError, OSError) as exc:
            log.append('  %-34s LOAD FAIL: %s' % (os.path.basename(path), exc))
            continue
        before = len(found)
        scan_ram(blob, tag, path, seen, found)
        log.append('  %-34s %d block(s)  [%s]'
                   % (os.path.basename(path), len(found) - before, tag))
        del blob


def load_blocks(paths, tag, seen, found, log):
    for path in paths:
        try:
            ram = extract_ram(path)
        except Exception as exc:                      # noqa: BLE001
            log.append('  %-34s LOAD FAIL: %s' % (os.path.basename(path), exc))
            continue
        before = len(found)
        scan_ram(ram, tag, path, seen, found)
        log.append('  %-34s %d new block(s)' % (os.path.basename(path),
                                                len(found) - before))
        del ram


# ------------------------------------------------------------ shipped table
def load_table():
    """{usa_c10: {vid: key}} exactly as build_v4.load_entries builds it."""
    table = collections.defaultdict(dict)
    with open(V3_ENTRIES) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            table[PROLOGUE_C10_USA][int(parts[1])] = int(parts[0])
    if os.path.exists(EXTRA_ENTRIES):
        with open(EXTRA_ENTRIES, encoding='utf-8') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3 or not parts[0].isdigit():
                    continue
                table[int(parts[0])][int(parts[2])] = int(parts[1])
    return table


# ------------------------------------------------------------------ helpers
def min_voice_id(blk):
    ids = [v for (_u, _k, v, _t) in blk['voices']]
    return min(ids) if ids else 1 << 30


def kind_of(blk, vid):
    for _u, kind, v, _t in blk['voices']:
        if v == vid:
            return kind
    return '?'


def read_string(blk, key):
    if not (0 <= key < len(blk['data'])):
        return ''
    end = blk['data'].find(b'\x00', key)
    if end < 0:
        end = len(blk['data'])
    raw = blk['data'][key:end]
    for enc in ('utf-8', 'shift_jis'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode('utf-8', 'replace')


def site_texts(blk, unit):
    """(preceding, following) CALL195 text for a voice site at `unit`."""
    prev = nxt = ''
    for u, key in blk['lines']:
        if u < unit and (not prev or u > prev[0]):
            prev = (u, key)
        if u > unit and not nxt:
            nxt = (u, key)
    return ((read_string(blk, prev[1]), prev[0]) if prev else ('', -1),
            (read_string(blk, nxt[1]), nxt[0]) if nxt else ('', -1))


def safe(text, limit=60):
    """ASCII-safe console rendering (the shell codepage is cp932)."""
    out = text.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')
    out = out.encode('ascii', 'replace').decode('ascii')
    return out[:limit] + ('...' if len(out) > limit else '')


# ------------------------------------------------------------------- census
def const_ids(blk):
    return set(v for (kind, v) in blk['census'] if kind == 'const')


def pair_blocks(jp, usa, overrides):
    """Pair JP and USA story blocks into chapters.

    Pair by CONST-ID OVERLAP, never by position: the two versions can have a
    different number of blocks on hand at any time (one USA chapter captured,
    its JP partner not yet), and a positional zip silently pairs a JP block
    with the wrong USA block the moment the counts differ.  Const-id spaces are
    chapter-partitioned with zero overlap, so overlap is the reliable signal.
    """
    if overrides:
        by_c10 = {b['c10']: b for b in jp + usa}
        pairs, used = [], set()
        for jc, uc in overrides:
            if jc in by_c10 and uc in by_c10:
                pairs.append((by_c10[jc], by_c10[uc]))
                used.update((jc, uc))
        return (pairs,
                [b for b in jp if b['c10'] not in used],
                [b for b in usa if b['c10'] not in used])

    scored = []
    for i, j in enumerate(jp):
        js = const_ids(j)
        for k, u in enumerate(usa):
            us = const_ids(u)
            if js and us:
                overlap = len(js & us)
                if overlap:
                    scored.append((overlap, i, k))
    scored.sort(key=lambda t: (-t[0], t[1], t[2]))
    pairs, used_j, used_u = [], set(), set()
    for _score, i, k in scored:
        if i in used_j or k in used_u:
            continue
        used_j.add(i)
        used_u.add(k)
        pairs.append((jp[i], usa[k]))
    pairs.sort(key=lambda p: min_voice_id(p[0]))
    return (pairs,
            [b for b in jp if b['c10'] not in {x['c10'] for x, _ in pairs}],
            [b for b in usa if b['c10'] not in {y['c10'] for _, y in pairs}])


def run(ram_jp, ram_usa, states_dir, overrides, out_report, out_tsv,
        use_dat=True, write=True):
    """Scan + census; write out_report/out_tsv only when write is True.

    --selftest passes write=False so it can never clobber the tracked
    report/TSV with a partial (state-less) run; it checks in-memory
    results only.
    """
    log = []
    seen, blocks = set(), []
    log.append('== inputs ==')
    for tag, path in sorted(SCRIPT_DAT.items()):
        if use_dat and os.path.isfile(path):
            load_raw([path], tag, seen, blocks, log)
    # every psp_ram_*.bin, tagged by content, so no dump is excluded by its name
    load_generic(sorted(glob.glob(os.path.join(WORK, 'psp_ram_*.bin'))),
                 seen, blocks, log)
    load_blocks(ram_jp, 'jp', seen, blocks, log)
    load_blocks(ram_usa, 'usa', seen, blocks, log)
    if states_dir:
        # tag by CONTENT (block_lang), not by filename
        load_generic(sorted(glob.glob(os.path.join(states_dir, '*.ppst'))),
                     seen, blocks, log)

    jp = [b for b in blocks if b['tag'] == 'jp']
    usa = [b for b in blocks if b['tag'] == 'usa']
    log.append('')
    log.append('== blocks found ==')
    for tag, group in (('jp', jp), ('usa', usa)):
        for b in sorted(group, key=lambda b: b['c10']):
            c = b['census']
            log.append('  %s c10=%-6d lines=%-5d const=%-4d f2=%-3d pair=%-4d'
                       '  textCALL=%-4d voiceCALL=%-4d'
                       '  (first from %s)'
                       % (tag, b['c10'], len(b['lines']),
                          sum(v for (k, _), v in c.items() if k == 'const'),
                          sum(v for (k, _), v in c.items() if k == 'f2'),
                          sum(v for (k, _), v in c.items() if k == 'pair'),
                          b['text_call'], b['voice_call'],
                          os.path.basename(b['src'] or '?')))

    pairs, jp_left, usa_left = pair_blocks(jp, usa, overrides)
    table = load_table()

    log.append('')
    log.append('== per-chapter coverage ==')
    log.append('  deleted = JP multiset - USA multiset (Counter arithmetic)')
    log.append('  rows needed = deleted const + deleted f2   '
               '(pair sites need no row: USA kept them)')
    tsv_rows = []
    summary = []
    for idx, (jb, ub) in enumerate(pairs, 1):
        jc, uc = jb['census'], ub['census']
        deleted = jc - uc                      # Counter: keeps positives only
        del_const = collections.Counter(
            {k: v for k, v in deleted.items() if k[0] == 'const'})
        del_f2 = collections.Counter(
            {k: v for k, v in deleted.items() if k[0] == 'f2'})
        del_pair = collections.Counter(
            {k: v for k, v in deleted.items() if k[0] == 'pair'})
        needed = sorted(vid for (kind, vid), cnt in deleted.items()
                        if kind in ('const', 'f2') for _ in range(cnt))
        present = table.get(ub['c10'], {})
        missing = [v for v in needed if v not in present]
        extra = sorted(v for v in present if v not in needed)
        dropped = [v for v in missing if v in KNOWN_DROPS]
        gaps = [v for v in missing if v not in KNOWN_DROPS]

        # key validity: every shipped row must be a real USA CALL195 line
        usa_keys = {key for _u, key in ub['lines']}
        bad_keys = sorted(v for v, key in present.items() if key not in usa_keys)

        # label by voice-id RANGE, not by discovery order: the ordinal is just
        # the Nth block we happened to capture, not the in-game chapter number
        cmin = min(const_ids(jb)) if const_ids(jb) else 0
        cmax = max(const_ids(jb)) if const_ids(jb) else 0
        label = KNOWN.get((jb['c10'], ub['c10']),
                          'chapter ? (ids %d-%d, #%d seen)'
                          % (cmin, cmax, idx))
        log.append('')
        log.append('  [%s]' % label)
        log.append('    jp c10=%-6d usa c10=%-6d' % (jb['c10'], ub['c10']))
        log.append('    JP   const=%d f2=%d pair=%d lines=%d'
                   % (sum(v for (k, _), v in jc.items() if k == 'const'),
                      sum(v for (k, _), v in jc.items() if k == 'f2'),
                      sum(v for (k, _), v in jc.items() if k == 'pair'),
                      len(jb['lines'])))
        log.append('    USA  const=%d f2=%d pair=%d lines=%d'
                   % (sum(v for (k, _), v in uc.items() if k == 'const'),
                      sum(v for (k, _), v in uc.items() if k == 'f2'),
                      sum(v for (k, _), v in uc.items() if k == 'pair'),
                      len(ub['lines'])))
        log.append('    deleted: const=%d f2=%d pair=%d   rows needed=%d'
                   % (sum(del_const.values()), sum(del_f2.values()),
                      sum(del_pair.values()), len(needed)))
        log.append('    shipped rows for usa c10=%d: %d' % (ub['c10'],
                                                            len(present)))
        if del_pair:
            log.append('    !! DELETED PAIR SITES %s - these play nothing in '
                       'the USA build and need rows' % sorted(
                           v for _k, v in del_pair.elements()))
        for v in dropped:
            log.append('    ok  intentional drop vid %d (%s)'
                       % (v, KNOWN_DROPS[v]))
        for v in gaps:
            log.append('    GAP vid %-6d (%s site) - no table row; line will '
                       'be silent' % (v, kind_of(jb, v)))
        for v in extra:
            log.append('    ?? extra row vid %-6d not in the deleted set '
                       '(key %d)' % (v, present[v]))
        for v in bad_keys:
            log.append('    !! row vid %-6d key %d is not a USA CALL195 line '
                       'in this block' % (v, present[v]))
        verdict = 'COMPLETE' if not gaps and not bad_keys and not del_pair else \
            ('PARTIAL (%d gap(s))' % len(gaps) if gaps or del_pair
             else 'KEY ERRORS')
        log.append('    verdict: %s' % verdict)
        summary.append((label, jb['c10'], ub['c10'], len(needed),
                        len(present), len(gaps), len(bad_keys),
                        sum(del_pair.values())))

        # bilingual rows: every vid the chapter needs, plus everything shipped
        jp_by_vid = {}
        for unit, kind, vid, _tgt in jb['voices']:
            jp_by_vid.setdefault(vid, (unit, kind))
        for vid in sorted(set(needed) | set(present)):
            unit, kind = jp_by_vid.get(vid, (-1, kind_of(jb, vid)))
            if unit >= 0:
                (jp_prev, jp_prev_u), (jp_next, jp_next_u) = site_texts(jb, unit)
            else:
                jp_prev = jp_prev_u = jp_next = jp_next_u = ''
            key = present.get(vid, -1)
            usa_txt = read_string(ub, key) if key >= 0 else ''
            tsv_rows.append([
                label.split(' ')[0], str(jb['c10']), str(ub['c10']), str(kind),
                str(vid), str(unit), str(jp_prev_u), str(jp_prev),
                str(jp_next_u), str(jp_next), str(key), str(usa_txt),
                'present' if vid in present else 'MISSING',
            ])

    for tag, leftover in (('jp', jp_left), ('usa', usa_left)):
        for b in leftover:
            log.append('')
            log.append('  [UNPAIRED %s] c10=%d lines=%d voices=%d - no partner '
                       'block found; dump RAM with that chapter loaded'
                       % (tag, b['c10'], len(b['lines']), len(b['voices'])))

    log.append('')
    log.append('== summary ==')
    log.append('  %-26s %7s %7s %7s %7s %6s %6s %6s'
               % ('chapter', 'need', 'ship', 'gaps', 'badkey', 'delpair',
                  'jp_c10', 'usa'))
    for (label, jc10, uc10, need, ship, gaps, bad, dp) in summary:
        log.append('  %-26s %7d %7d %7d %7d %6d %6d %6d'
                   % (label[:26], need, ship, gaps, bad, dp, jc10, uc10))
    log.append('')
    log.append('  A row is needed only for JP voice sites the USA script '
               'deleted.')
    log.append('  GAP = line will be silent. badkey = row points at a '
               'non-existent line.')
    log.append('  delpair>0 = USA deleted native pair triggers: silent too, '
               'and not fixable by the table alone.')

    if write:
        with open(out_report, 'w', encoding='utf-8') as f:
            f.write('\n'.join(log) + '\n')
        with open(out_tsv, 'w', encoding='utf-8', newline='') as f:
            f.write('\t'.join(['chapter', 'jp_c10', 'usa_c10', 'kind', 'vid',
                               'jp_unit', 'jp_prev_unit', 'jp_prev_text',
                               'jp_next_unit', 'jp_next_text', 'usa_key',
                               'usa_text', 'status']) + '\n')
            for row in tsv_rows:
                f.write('\t'.join(c.replace('\t', ' ').replace('\n', ' ')
                                  for c in row) + '\n')
    return log, summary, pairs


# ----------------------------------------------------------------- selftest
def selftest(ram_jp, ram_usa, states_dir, use_dat=True):
    log, summary, pairs = run(ram_jp, ram_usa, states_dir, [], REPORT, TSV,
                              use_dat, write=False)
    by_c10 = {(j['c10'], u['c10']): (j, u) for j, u in pairs}
    checks, failed, skipped = [], 0, 0

    def check(name, ok, detail):
        nonlocal failed
        checks.append((name, ok, detail))
        if not ok:
            failed += 1

    def known(jc, uc):
        return by_c10.get((jc, uc))

    # --- prologue: documented in RE_notes.md "Post-prologue completeness"
    pair = known(43032, 38381)
    if not pair:
        skipped += 1
        print('SKIP prologue: jp c10=43032 / usa c10=38381 blocks not in the '
              'scanned dumps')
    else:
        jb, ub = pair
        jc, uc = jb['census'], ub['census']
        jconst = sum(v for (k, _), v in jc.items() if k == 'const')
        uconst = sum(v for (k, _), v in uc.items() if k == 'const')
        jf2 = sum(v for (k, _), v in jc.items() if k == 'f2')
        jpair = sum(v for (k, _), v in jc.items() if k == 'pair')
        upair = sum(v for (k, _), v in uc.items() if k == 'pair')
        check('prologue JP const = 392', jconst == 392, 'got %d' % jconst)
        check('prologue USA retained const = 68', uconst == 68,
              'got %d' % uconst)
        check('prologue JP f2 = 15', jf2 == 15, 'got %d' % jf2)
        check('prologue pair 505 = 505 (JP=USA)', jpair == upair == 505,
              'jp %d usa %d' % (jpair, upair))
        rows = load_table().get(38381, {})
        check('prologue shipped rows = 339', len(rows) == 339,
              'got %d' % len(rows))
        deleted = jc - uc
        needed = sorted(v for (kind, v), cnt in deleted.items()
                        if kind in ('const', 'f2') for _ in range(cnt))
        gaps = [v for v in needed if v not in rows]
        check('prologue has no gaps (vid 122 reinstated 2026-09-25)',
              gaps == [], 'gaps %s' % gaps)

    # --- chapter 1: RE_notes.md records exactly one deleted trigger
    pair = known(55506, 50098)
    if not pair:
        skipped += 1
        print('SKIP ch.1: jp c10=55506 / usa c10=50098 blocks not in the '
              'scanned dumps')
    else:
        jb, ub = pair
        deleted = jb['census'] - ub['census']
        deleted_ids = sorted(v for (kind, v), cnt in deleted.items()
                             if kind in ('const', 'f2')
                             for _ in range(cnt))
        rows = load_table().get(50098, {})
        check('ch.1 exactly one deleted trigger', deleted_ids == [2287],
              'deleted %s' % deleted_ids)
        check('ch.1 row present (vid 2287)', rows.get(2287) == 191506,
              'rows %s' % rows)
        jpair = sum(v for (k, _), v in jb['census'].items() if k == 'pair')
        upair = sum(v for (k, _), v in ub['census'].items() if k == 'pair')
        check('ch.1 pair 516 = 516 (JP=USA)', jpair == upair == 516,
              'jp %d usa %d' % (jpair, upair))

    print()
    for name, ok, detail in checks:
        print('%-46s %s  %s' % (name, 'PASS' if ok else 'FAIL', detail))
    print('\n%d check(s), %d failed, %d chapter(s) skipped'
          % (len(checks), failed, skipped))
    print('--selftest wrote nothing; report/TSV stay as committed:')
    print('  regenerate with a plain run: %s' % REPORT)
    return 1 if failed else 0


# --------------------------------------------------------------------- main
def main(argv):
    overrides = []
    ram_jp = ram_usa = None
    states_dir = None
    do_self = False
    use_dat = True
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--selftest':
            do_self = True
        elif a == '--no-dat':
            use_dat = False
        elif a == '--pair':
            i += 1
            for item in argv[i].split(','):
                j, u = item.split('=')
                overrides.append((int(j), int(u)))
        elif a == '--ram-jp':
            i += 1
            ram_jp = sorted(glob.glob(argv[i]))
        elif a == '--ram-usa':
            i += 1
            ram_usa = sorted(glob.glob(argv[i]))
        elif a == '--states':
            i += 1
            states_dir = argv[i]
        elif a in ('-h', '--help'):
            print(__doc__)
            return 0
        else:
            print('unknown arg %r (try --help)' % a)
            return 2
        i += 1

    if ram_jp is None:
        ram_jp = []
    if ram_usa is None:
        ram_usa = []

    if do_self:
        return selftest(ram_jp, ram_usa, states_dir, use_dat)

    log, _summary, _pairs = run(ram_jp, ram_usa, states_dir, overrides,
                                REPORT, TSV, use_dat)
    for line in log:
        print(safe(line, 200))
    print('\nreport: %s' % REPORT)
    print('tsv   : %s' % TSV)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
